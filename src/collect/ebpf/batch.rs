use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd};

use aya_obj::generated::{bpf_attr, bpf_cmd};

use super::{VfsAggKey, VfsAggValue};

pub(super) const MAX_VFS_AGG_ENTRIES: usize = 8_192;
const BUSY_RETRIES: usize = 8;

#[derive(Debug)]
struct BatchPage {
    entries: Vec<(VfsAggKey, VfsAggValue)>,
    next_cursor: VfsAggKey,
    exhausted: bool,
}

pub(super) fn drain(fd: BorrowedFd<'_>) -> Result<Vec<(VfsAggKey, VfsAggValue)>, String> {
    drain_with(|cursor, capacity| lookup_and_delete(fd, cursor, capacity))
}

fn drain_with(
    mut lookup: impl FnMut(Option<VfsAggKey>, usize) -> io::Result<BatchPage>,
) -> Result<Vec<(VfsAggKey, VfsAggValue)>, String> {
    let mut entries = Vec::new();
    let mut cursor: Option<VfsAggKey> = None;

    while entries.len() < MAX_VFS_AGG_ENTRIES {
        let remaining = MAX_VFS_AGG_ENTRIES - entries.len();
        let page = lookup(cursor, remaining)
            .map_err(|error| format!("cannot drain eBPF VFS aggregation map: {error}"))?;
        if page.entries.len() > remaining {
            return Err(format!(
                "eBPF VFS batch returned {} entries for a {remaining}-entry buffer",
                page.entries.len()
            ));
        }

        let made_progress = !page.entries.is_empty();
        entries.extend(page.entries);
        if page.exhausted || entries.len() == MAX_VFS_AGG_ENTRIES {
            break;
        }
        if !made_progress {
            return Err("eBPF VFS batch drain made no progress".to_string());
        }
        cursor = Some(page.next_cursor);
    }

    Ok(entries)
}

fn lookup_and_delete(
    fd: BorrowedFd<'_>,
    cursor: Option<VfsAggKey>,
    capacity: usize,
) -> io::Result<BatchPage> {
    retry_busy(|| lookup_and_delete_once(fd, cursor, capacity))
}

fn retry_busy(mut lookup: impl FnMut() -> io::Result<BatchPage>) -> io::Result<BatchPage> {
    for attempt in 0..=BUSY_RETRIES {
        match lookup() {
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) && attempt < BUSY_RETRIES => {
                // Hash-map batch operations can collide with a BPF-side map
                // update and return EBUSY before processing an entry. The
                // kernel contract explicitly leaves retrying to userspace.
            }
            result => return result,
        }
    }
    unreachable!("bounded eBPF batch retry loop always returns")
}

fn lookup_and_delete_once(
    fd: BorrowedFd<'_>,
    cursor: Option<VfsAggKey>,
    capacity: usize,
) -> io::Result<BatchPage> {
    debug_assert!(capacity <= MAX_VFS_AGG_ENTRIES);
    let mut keys = vec![VfsAggKey::default(); capacity];
    let mut values = vec![VfsAggValue::default(); capacity];
    let mut next_cursor = VfsAggKey::default();
    let cursor_value = cursor.unwrap_or_default();
    let mut attr = unsafe { std::mem::zeroed::<bpf_attr>() };

    let batch = unsafe { &mut attr.batch };
    batch.in_batch = cursor
        .map(|_| (&cursor_value as *const VfsAggKey) as u64)
        .unwrap_or_default();
    batch.out_batch = (&mut next_cursor as *mut VfsAggKey) as u64;
    batch.keys = keys.as_mut_ptr() as u64;
    batch.values = values.as_mut_ptr() as u64;
    batch.count = capacity as u32;
    batch.map_fd = fd.as_raw_fd() as u32;

    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_BATCH as libc::c_uint,
            &mut attr,
            size_of::<bpf_attr>(),
        )
    };
    let count = unsafe { attr.batch.count as usize };
    if count > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("kernel returned {count} entries for a {capacity}-entry VFS batch"),
        ));
    }
    keys.truncate(count);
    values.truncate(count);
    let entries = keys.into_iter().zip(values).collect();

    if result == 0 {
        return Ok(BatchPage {
            entries,
            next_cursor,
            exhausted: false,
        });
    }

    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOENT) => Ok(BatchPage {
            entries,
            next_cursor,
            exhausted: true,
        }),
        // For non-EFAULT errors the kernel reports successfully processed
        // entries through count. Preserve those entries and continue from the
        // returned cursor instead of discarding data and disabling collection.
        Some(libc::EBUSY) | Some(libc::ENOSPC) if !entries.is_empty() => Ok(BatchPage {
            entries,
            next_cursor,
            exhausted: false,
        }),
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(inode: u64) -> (VfsAggKey, VfsAggValue) {
        (
            VfsAggKey {
                inode,
                ..VfsAggKey::default()
            },
            VfsAggValue::default(),
        )
    }

    #[test]
    fn combines_multiple_pages_and_accepts_terminal_entries() {
        let mut calls = 0;
        let entries = drain_with(|cursor, capacity| {
            calls += 1;
            assert!(capacity <= MAX_VFS_AGG_ENTRIES);
            match calls {
                1 => {
                    assert_eq!(cursor, None);
                    Ok(BatchPage {
                        entries: vec![entry(1), entry(2)],
                        next_cursor: VfsAggKey {
                            inode: 7,
                            ..VfsAggKey::default()
                        },
                        exhausted: false,
                    })
                }
                2 => {
                    assert_eq!(cursor.unwrap().inode, 7);
                    Ok(BatchPage {
                        entries: vec![entry(3)],
                        next_cursor: VfsAggKey {
                            inode: 9,
                            ..VfsAggKey::default()
                        },
                        exhausted: true,
                    })
                }
                _ => unreachable!(),
            }
        })
        .unwrap();

        assert_eq!(calls, 2);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].0.inode, 3);
    }

    #[test]
    fn enforces_the_kernel_map_capacity() {
        let entries = drain_with(|_, capacity| {
            Ok(BatchPage {
                entries: (0..capacity).map(|index| entry(index as u64)).collect(),
                next_cursor: entry(1).0,
                exhausted: false,
            })
        })
        .unwrap();

        assert_eq!(entries.len(), MAX_VFS_AGG_ENTRIES);
    }

    #[test]
    fn rejects_zero_progress_and_syscall_errors() {
        let stalled = drain_with(|_, _| {
            Ok(BatchPage {
                entries: Vec::new(),
                next_cursor: entry(1).0,
                exhausted: false,
            })
        });
        assert_eq!(
            stalled.unwrap_err(),
            "eBPF VFS batch drain made no progress"
        );

        let failed = drain_with(|_, _| Err(io::Error::from_raw_os_error(libc::EINVAL)));
        assert!(failed.unwrap_err().contains("Invalid argument"));
    }

    #[test]
    fn retries_transient_busy_batch_operations() {
        let mut calls = 0;
        let page = retry_busy(|| {
            calls += 1;
            if calls <= BUSY_RETRIES {
                Err(io::Error::from_raw_os_error(libc::EBUSY))
            } else {
                Ok(BatchPage {
                    entries: vec![entry(1)],
                    next_cursor: entry(2).0,
                    exhausted: true,
                })
            }
        })
        .unwrap();

        assert_eq!(calls, BUSY_RETRIES + 1);
        assert_eq!(page.entries.len(), 1);
    }

    #[test]
    fn rejects_a_page_larger_than_the_requested_buffer() {
        let failed = drain_with(|_, capacity| {
            Ok(BatchPage {
                entries: (0..=capacity).map(|index| entry(index as u64)).collect(),
                next_cursor: entry(1).0,
                exhausted: false,
            })
        });
        assert!(failed.unwrap_err().contains("entry buffer"));
    }
}
