---
layout: single
title:  "io_uring from Userland"
date: 2026-03-27
classes: wide
tags:
  - Security Research
  - Linux
  - io_uring
---

You know the pains if you've written performance sensitive I/O code on Linux. Every `read()` and `write()` is a round trip into the kernel. POSIX AIO was a mess, and `epoll` still makes you do the actual I/O call yourself once an fd is ready.

`io_uring` introduced in Linux 5.1 fixes this. It sets up two ring buffers shared between your process and the kernel. You drop requests into the submission queue, the kernel drops results into the completion queue. No context switches required!

To understand how `io_uring` works in userland, we'll take a simple example where we'll be reading from a file into a buffer. Below is the code which we'll be analyzing:
```cpp
#include <liburing.h>
#include <fcntl.h>
#include <stdio.h>
int main(void) {
    struct io_uring ring;
    io_uring_queue_init(32, &ring, 0);   

    int fd = open("file.txt", O_RDONLY);
    char buf[4096];

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);

    io_uring_prep_read(sqe, fd, buf, sizeof(buf), 0);
    sqe->user_data = 42;  

    io_uring_submit(&ring);

    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);

    printf("read %d bytes\n", cqe->res);

    io_uring_cqe_seen(&ring, cqe);
    io_uring_queue_exit(&ring);
    return 0;
}
```
our file.txt is a simple text file as the name implies, and holds the string "Hello world!".
Digging inside gdb:
We first call `io_uring_queue_init` with the following arguments:

![diagram](/assets/images/Pasted image 20260323192138.png) 


where `0x7fffffffcd30` is the address of our `io_uring` object `ring`. We then call `io_uring_queue_init`.
```cpp
int io_uring_queue_init(unsigned entries, struct io_uring *ring, unsigned flags)
{
struct io_uring_params p;
memset(&p, 0, sizeof(p));
p.flags = flags;

return io_uring_queue_init_params(entries, ring, &p);
}
```
We create an object of `io_uring_params` and set all fields of it to 0, then set the flags of `io_uring_params p` as NULL, since that's what we passed in place of flags.
```cpp
struct io_uring_params
{
__u32 sq_entries;
__u32 cq_entries;
__u32 flags;
__u32 sq_thread_cpu;
__u32 sq_thread_idle;
__u32 features;
__u32 wq_fd;
__u32 resv[3];
struct io_sqring_offsets sq_off;
struct io_cqring_offsets cq_off;
};
```
now....

![diagram](/assets/images/Pasted image 20260323193014.png)

moving ahead... we call `io_uring_queue_init_params` with the following arguments:

![diagram](/assets/images/Pasted image 20260327213150.png)

Keep in mind that `entries` is the number of entries we want which is the first argument, `ring` is our struct `io_uring` object which is our second argument, and `p` is our `io_uring_params` struct object which is currently all set to 0, our third argument.

![diagram](/assets/images/Pasted image 20260327212857.png)

```cpp
int io_uring_queue_init_params(unsigned entries, struct io_uring *ring, struct io_uring_params *p)
{
	int ret;
	
	ret = io_uring_queue_init_try_nosqarr(entries, ring, p, NULL, 0);
	return ret >= 0 ? 0 : ret;
}
```
`io_uring_queue_init_try_nosqarr` expects 5 arguments. We are already familiar with the first 3, the 4th one is the address of our buffer and 5th one is the size of our buffer.

![diagram](/assets/images/Pasted image 20260327213425.png)

![diagram](/assets/images/Pasted image 20260327213527.png)

```cpp
static int io_uring_queue_init_try_nosqarr(unsigned entries, struct io_uring *ring, struct io_uring_params *p, void *buf, size_t buf_size)
{
	unsigned flags = p->flags;
	int ret;

	p->flags |= IORING_SETUP_NO_SQARRAY;
	ret = __io_uring_queue_init_params(entries, ring, p, buf, buf_size);

	/* don't fallback if explicitly asked for NOSQARRAY */
	if (ret != -EINVAL || (flags & IORING_SETUP_NO_SQARRAY))
		return ret;

	p->flags = flags;
	return __io_uring_queue_init_params(entries, ring, p, buf, buf_size);
}
```
here we see we've set flags in our `p` object by ORing with `IORING_SETUP_NO_SQARRAY`. 

![diagram](/assets/images/Pasted image 20260323195646.png)

```cpp
#define IORING_SETUP_NO_SQARRAY (1U << 16)
```
Setting `IORING_SETUP_NO_SQARRAY` says **skip the SQ array entirely**. The kernel reads SQEs directly in order without the indirection layer and then calls `__io_uring_queue_init_params`.  

![diagram](/assets/images/Pasted image 20260327213825.png)

![diagram](/assets/images/Pasted image 20260327213926.png)

seeing our flags which we set in `p`:

![diagram](/assets/images/Pasted image 20260327214047.png)

We won't go into the depth of that since it's a pretty long function. However, it makes some checks and then calls `__sys_io_uring_setup`...
```cpp
fd = __sys_io_uring_setup(entries, p);
```
which further invokes `__do_syscall2` with the appropriate syscall number and number of entries and `io_uring_params` object `p` as arguments. 
```cpp
static inline int __sys_io_uring_setup(unsigned int entries, struct io_uring_params *p)
{
	return (int) __do_syscall2(__NR_io_uring_setup, entries, p);
}
```
![diagram](/assets/images/Pasted image 20260327214453.png)

We aren't going to go into the details of the system call for now since that will probably covered in future posts. Moving on, we backtrack to `__io_uring_queue_init_params`  and check the file descriptor returned to us by `__sys_io_uring_setup` since we did
```cpp 
fd = __sys_io_uring_setup(entries, p);
```

![diagram](/assets/images/Pasted image 20260327214909.png)

our green arrows tell us till where we have backtracked and green coloured box is our current function we're analyzing.

![diagram](/assets/images/Pasted image 20260324001655.png)

 And... what is happening with `fd` here?

When we call `sys_io_uring_setup()`, the kernel does two things simultaneously:

1. First, it creates the ring buffers internally
2. Second, it returns a **file descriptor** representing that ring

That file descriptor is our handle to the entire `io_uring instance`. Every future operation such as submitting requests, waiting for completions, registering buffers all of it goes through that beautiful `fd`.  Continuing `__io_uring_queue_init_params`:
```c
fd = sys_io_uring_setup(entries, p);
if (fd < 0) { ...
```
If `fd` is negative, we know our setup failed. But before returning the error, the code has to tidy up any memory it already allocated because by this point, memory *may* have already been set aside for the SQ and CQ rings even though the kernel side setup never completed, but remember we made a syscall.
```c
if ((p->flags & IORING_SETUP_NO_MMAP) && 
    !(ring->int_flags & INT_FLAG_APP_MEM)) {
    sys_munmap(ring->sq.sqes, ring->sq.sqes_sz);
    io_uring_unmap_rings(&ring->sq, &ring->cq);
}
```

This says that if we allocated our own memory for the rings (`NO_MMAP` mode) and that memory belongs to the kernel not the application (no `INT_FLAG_APP_MEM`), unmap it now before bailing out. If the application provided its own memory, we leave it alone. It's not our headache, and since we never set `IORING_SETUP_NO_MMAP` and `INT_FLAG_APP_MEM` and neither is our `fd` lower than 0, we don't come on this path. GDB output tells us that no memory has been allocated for userland, however, recall that an `fd` having `0x3` was returned to us by the kernel. When `sys_io_uring_setup()` returned `fd 3` successfully, the kernel had already done the memory work, but we had not, and later we'll see that when we `mmap` in userspace, we use the `fd` returned to us by the kernel.

![diagram](/assets/images/Pasted image 20260327221506.png)

For the *mapping* success path, we take two routes. The first path is the following:
```c
if (!(p->flags & IORING_SETUP_NO_MMAP)) {
    ret = io_uring_queue_mmap(fd, p, ring);
    }
```

Here the kernel allocated the ring memory itself. But that memory lives in kernel space. To actually use it from your application, which is in userspace, we need to map it into our process's address space, and that's what `mmap` does. `io_uring_queue_mmap` uses the `fd` to ask the kernel "let me see the ring memory you allocated." 

![diagram](/assets/images/Pasted image 20260327222915.png)

now we have the following mates populated.

![diagram](/assets/images/Pasted image 20260327221814.png)

## talking of io_uring_mmap....
After the kernel creates the `io_uring` object ring, it lives in kernel memory. Our process cannot touch it yet. This function's entire job is to bridge that gap. It maps the kernel's ring memory into our process's address space so we can read and write it directly just like normal arrays. Three separate regions need to be mapped:

1. The SQ ring  --> submission queue metadata and index
2. The CQ ring  --> completion queue metadata and entries  
3. The SQE array --> the actual submission queue entries (de SQEs)

first we calculate how much memory each ring needs:
```c
sq->ring_sz = p->sq_off.array + p->sq_entries * sizeof(unsigned);
cq->ring_sz = p->cq_off.cqes + params_cq_size(p, p->cq_entries);
```

Before mapping anything, the code sees exactly how many bytes each ring takes. The SQ ring size is the offset to its array plus enough space for all its entries. Same logic for the CQ ring. We see a new struct here `sq_off` . It is a struct called `io_sqring_offsets` that the kernel fills in during setup. It tells you the byte offset of every important field within the SQ ring memory. `.array` specifically is the offset to where the index array begins. Everything before this offset is metadata such as the head pointer, tail pointer, ring mask, flags, and so on. So `p->sq_off.array` tells us the index array starts this many bytes into the ring.

**`p->sq_entries`** is the number of entries the SQ ring can hold. We specified this when calling `io_uring_setup()`. The kernel may round it up to the next power of two, and it writes the actual value back into `p->sq_entries`. Each slot in the index array is one `unsigned int`, which is 4 bytes. This is the SQ array we discussed earlier, and it's the index that maps queue positions to actual SQE slots.

So the total size is: **"start of the index array" + "space for all the index entries"**. That gets you the byte position of the very last byte in the ring, which is exactly how many bytes you need to map.
```cpp
struct io_sqring_offsets 
{
uint head;
uint tail;
uint ring_mask;
uint ring_entries;
uint flags;
uint dropped;
uint array;
uint resv1;
ulong resv2;
}
```
this makes:

![diagram](/assets/images/Pasted image 20260324010108.png)

now we have...
```c
if (p->features & IORING_FEAT_SINGLE_MMAP) {
    if (cq->ring_sz > sq->ring_sz)
        sq->ring_sz = cq->ring_sz;
    cq->ring_sz = sq->ring_sz;
}
```

Newer kernels support a feature called `IORING_FEAT_SINGLE_MMAP`. Instead of mapping the SQ and CQ rings separately, both rings are packed into one single contiguous memory region. This reduces the number of `mmap` calls from two down to one. To make this work, both rings need to be the same size  so whichever is larger, the other is padded up to match.

![diagram](/assets/images/Pasted image 20260324010712.png)

since its all ones, and...
```cpp
#define IORING_FEAT_SINGLE_MMAP (1U << 0)
```
so we take this branch and equate our stuff.
Now comes the turn to map the SQ ring:
```c
sq->ring_ptr = __sys_mmap(0, sq->ring_sz, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE, fd,
                          IORING_OFF_SQ_RING);
```

This is the actual mapping call. Breaking down the arguments:

- `0` --> let the kernel pick where in our process's address space to place it
- `sq->ring_sz` --> map exactly this many bytes
- `PROT_READ | PROT_WRITE` --> our process needs to both read and write this memory
- `MAP_SHARED` --> changes are shared with the kernel, not private to our process. This is what makes `io_uring`'s zero copy magic work. We write an SQE in this memory and the kernel sees it immediately without any sort of copying.
- `MAP_POPULATE` --> pre-fault the pages into the RAM right now rather than lazily on first access avoiding page faults later during the hot I/O paths.
- `fd` --> the `io_uring` file descriptor, telling the kernel which ring to map.
- `IORING_OFF_SQ_RING` --> a special offset that tells the kernel "I want the SQ ring region specifically".

If this fails, we of course bail out immediately.
```c
if (p->features & IORING_FEAT_SINGLE_MMAP) {
    cq->ring_ptr = sq->ring_ptr;
} else {
    cq->ring_ptr = __sys_mmap(..., IORING_OFF_CQ_RING);
}
```

If single mmap is supported, the CQ ring is already inside the same memory region as the SQ ring, so just point `cq->ring_ptr` at the same address. No second mapping is needed. If not, then do a second `mmap` call for the CQ ring separately using `IORING_OFF_CQ_RING` as the offset.

![diagram](/assets/images/Pasted image 20260324012809.png)

Now we map the SQE array:
```c
sq->sqes = __sys_mmap(0, sq->sqes_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
```

The SQE array is always mapped separately even with single mmap, the actual SQE slots live in their own region. This is the memory where we physically write our `io_uring_sqe` structs when preparing requests. `IORING_OFF_SQES` tells the kernel "I want the SQE array region specifically."

Setting up our pointers....
```c
io_uring_setup_ring_pointers(p, sq, cq);
return 0;
```
![diagram](/assets/images/Pasted image 20260328010935.png)


Now that all three regions are mapped into our process, this function is called `io_uring_setup_ring_pointers` with the arguments:

![diagram](/assets/images/Pasted image 20260328011228.png)

We will shortly be discussing `io_uring_setup_ring_pointers` since it's going to be called from `__io_queue_init_params` as well. Looking at our structs after returning back from `io_uring_mmap`...

![diagram](/assets/images/Pasted image 20260324012624.png)

Now our struct `io_uring_sq` is populated. similarly,

![diagram](/assets/images/Pasted image 20260324012649.png)

We also return from `io_uring_queue_mmap`.
After this call, our process can read and write the SQ and CQ rings directly as if they were just normal arrays in our RAM. If that mapping fails, the `fd` is closed and the error is returned. We are going to have many pointers both from userland and kernel land pointing at our memory, but for understanding purposes, if we take an example of how SQEs exist in memory:

![diagram](/assets/images/Pasted image 20260327225026.png)

and so does the rest exist in memory.

Our route 2 is the following:
```c
else {
    io_uring_setup_ring_pointers(p, &ring->sq, &ring->cq);
}
```
lets dive into it

![diagram](/assets/images/Pasted image 20260328002207.png)

We call this function with the following arguments:

![diagram](/assets/images/Pasted image 20260328002616.png)

## The Goldmine:
```cpp
void io_uring_setup_ring_pointers(struct io_uring_params *p,
				  struct io_uring_sq *sq,
				  struct io_uring_cq *cq)
{
	sq->khead = sq->ring_ptr + p->sq_off.head;
	sq->ktail = sq->ring_ptr + p->sq_off.tail;
	sq->kring_mask = sq->ring_ptr + p->sq_off.ring_mask;
	sq->kring_entries = sq->ring_ptr + p->sq_off.ring_entries;
	sq->kflags = sq->ring_ptr + p->sq_off.flags;
	sq->kdropped = sq->ring_ptr + p->sq_off.dropped;
	if (!(p->flags & IORING_SETUP_NO_SQARRAY))
		sq->array = sq->ring_ptr + p->sq_off.array;

	cq->khead = cq->ring_ptr + p->cq_off.head;
	cq->ktail = cq->ring_ptr + p->cq_off.tail;
	cq->kring_mask = cq->ring_ptr + p->cq_off.ring_mask;
	cq->kring_entries = cq->ring_ptr + p->cq_off.ring_entries;
	cq->koverflow = cq->ring_ptr + p->cq_off.overflow;
	cq->cqes = cq->ring_ptr + p->cq_off.cqes;
	if (p->cq_off.flags)
		cq->kflags = cq->ring_ptr + p->cq_off.flags;

	sq->ring_mask = *sq->kring_mask;
	sq->ring_entries = *sq->kring_entries;
	cq->ring_mask = *cq->kring_mask;
	cq->ring_entries = *cq->kring_entries;
}
```
Just take a moment and admire its beauty. How everything seems to make sense now...

After `mmap` completes, our process has a raw blob of shared memory. It knows the blob starts at `ring_ptr` and is `ring_sz` bytes large. But it has no idea where inside that blob the head pointer lives, where the tail pointer lives, where the entries are, and so on.

This function's entire job is to **calculate the address of every important field** inside that blob and store those addresses so the rest of the library can just do `*sq->khead` instead of doing pointer arithmetic every single time. Think of it like receiving a moving box full of items with no labels. This function opens the box, finds every item, and sticks a label on each one so you can grab anything instantly later.

![diagram](/assets/images/Pasted image 20260328003511.png){: style="display:block; margin:auto;" }

Note that every single line follows the same formula:
```c
sq->khead = sq->ring_ptr + p->sq_off.head;
```

- `sq->ring_ptr` --> the start address of the mapped memory blob
- `p->sq_off.head` --> the byte offset of the head field within that blob, as told to us by the kernel during setup
- Adding them together gives the **exact memory address** of that field
so if we take the example of `sq->kring_mask`:

![diagram](/assets/images/Pasted image 20260328003749.png)

The same happens with other fields and with cq ring fields. If we take a look at the last 4 lines:
```c
sq->ring_mask    = *sq->kring_mask;
sq->ring_entries = *sq->kring_entries;
cq->ring_mask    = *cq->kring_mask;
cq->ring_entries = *cq->kring_entries;
```

These dereference the pointers immediately to **save the values locally**. The ring mask and ring entries never change after setup, the kernel will never modify them. So instead of dereferencing a shared memory pointer every single time we need the mask, we copy the value once into a plain local field and read that instead. In it we already provided the memory ourselves, so there is nothing to map. The kernel just needs to set up the internal pointers so the SQ and CQ structs know where their head, tail, and data regions are within the memory provided. `io_uring_setup_ring_pointers` does this job, no mapping needed, just pointer arithmetic. since we never set `IORING_SETUP_NO_MMAP`

now lets return

![diagram](/assets/images/Pasted image 20260328004143.png)

now we do...
```cpp
sq_entries = ring->sq.ring_entries;
if (!(p->flags & IORING_SETUP_NO_SQARRAY)) {
    sq_array = ring->sq.array;
    for (index = 0; index < sq_entries; index++)
        sq_array[index] = index;
}
```

since we already set `IORING_SETUP_NO_SQARRAY`, so we wont take this branch which was supposed to set sq_array.

Remember the SQ array? The middleman index that maps queue positions to SQE slots? Normally it exists to allow reordering, meaning slot 0 in the queue could point to SQE 5, slot 1 could point to SQE 2, and so on. But almost nobody ever reorders. So this code sets up the simplest possible mapping, **slot 0 points to SQE 0, slot 1 points to SQE 1, slot 2 points to SQE 2**, and so on straight through. The array just maps every position directly to the same numbered SQE slot.
```c
ring->features = p->features;
ring->flags = p->flags;
ring->enter_ring_fd = fd;
```

Three simple values copied from the setup parameters into the ring struct so the rest of the library can access them without going back to `p` every time.
```c
if (p->flags & IORING_SETUP_REGISTERED_FD_ONLY) {
    ring->ring_fd = -1;
    ring->int_flags |= INT_FLAG_REG_RING | INT_FLAG_REG_REG_RING;
} else {
    ring->ring_fd = fd;
}
```
Since `IORING_SETUP_REGISTERED_FD_ONLY`  was never set, we also don't take this branch, but this is actually where `ring_fd` and `enter_ring_fd` diverge. In normal mode we do `ring->ring_fd = fd`.  We use the regular OS file descriptor for everything.

In `IORING_SETUP_REGISTERED_FD_ONLY` mode, the ring was set up with a **registered file descriptor** instead of a normal one. Registered file descriptors are stored in the kernel's own table rather than our process's file descriptor table. From a very high level `struct io_rsrc_data` is used to keep metadata about a set of registered resources and track their reference count etc, `tags` is a 2D array of tags or identifiers and `struct io_ring_ctx`is a pointer to the `io_uring` context which ties the resource data to a specific `io_uring` instance. An object of `io_ring_ctx` holds the state of the ring.

![diagram](/assets/images/Pasted image 20260328164528.png){: style="display:block; margin:auto;" }

They are faster to look up but cannot be used like normal fds in all situations. So `ring->ring_fd` is set to `-1` meaning  that "there is no normal fd for this ring" and two internal flags are set:
- `INT_FLAG_REG_RING` --> "this ring uses a registered fd"
- `INT_FLAG_REG_REG_RING` --> "the registered fd was registered by the setup process itself, not manually by the user"
and we do some other checks. 
then we return our already zeroed out `ret` back to `io_uring_queue_init_try_nosqarr`, then back to `io_uring_queue_init_params` and then return it to `io_uring_queue_init`, which returns it to our `main` function which isn't getting saved anywhere. This is how the struct gets prepared. pretty... twisty. 

![diagram](/assets/images/Pasted image 20260328163535.png)

We then continue to `io_uring_get_sqe`, which takes us to `_io_uring_get_sqe`. Because `io_uring_prep_read` needs somewhere to write the operation details into. Think of it this way, that the SQE is a form. `io_uring_get_sqe` hands us a blank form. `io_uring_prep_read` fills it out. 
```cpp
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, fd, buf, sizeof(buf), 0);     
```
 `_io_uring_get_sqe` 's job is simple, to find the next available empty SQE slot in the ring and hand it back to us. If the ring is full, return NULL. We call `_io_uring_get_sqe` with one argument: 
 ```cpp
 return _io_uring_get_sqe(ring);
 ```

![diagram](/assets/images/Pasted image 20260328165659.png)

### The two pointers that matter

```c
unsigned head = io_uring_load_sq_head(ring), tail = sq->sqe_tail;
```

The ring operates like a circular queue tracked by two numbers:
- **`head`** is where the kernel is currently consuming from. The kernel advances this as it picks up and processes our submissions. 
- **`tail`** is where we are currently producing to. We advance this every time you add a new SQE. We own this.

![diagram](/assets/images/anusf.gif){: style="display:block; margin:auto;" }

The number of SQEs currently in flight which are submitted but not yet consumed by the kernel is always `tail - head`.
```c
if (tail - head >= sq->ring_entries)
    return NULL;
```

If the distance between tail and head has reached the ring's total capacity, every slot is occupied and there is nowhere to put a new SQE in, so we return NULL. 

![diagram](/assets/images/Pasted image 20260328171520.png){: style="display:block; margin:auto;" }

The caller must wait for the kernel to consume some entries before submitting more. Now lets find the actual slot:
```c
sqe = &sq->sqes[(tail & sq->ring_mask) << io_uring_sqe_shift(ring)];
```

Three things are happening here:

1- **`tail & sq->ring_mask`** The ring mask is `sq_entries - 1` (since entry count is always a power of two).

![diagram](/assets/images/Pasted image 20260328171706.png)

ANDing the tail index with it wraps the tail around the ring which is the power of two modulo trick. So if you have 256 entries and tail is 257, you get slot 1.

2- **`<< io_uring_sqe_shift(ring)`** This accounts for the fact that `io_uring` supports two SQE sizes:
- Normal SQEs: 64 bytes --> shift of 0 (1 slot = 1 SQE)
- Big SQEs (`IORING_SETUP_SQE128`): 128 bytes --> shift of 1 (1 slot = 2 × 64 byte units). So here one slot is of 128 bytes, that's why we need to shift once, to get double space.

So the shift scales the logical slot index into the correct offset within the `sqes` array, which is always typed as an array of the base 64 byte `io_uring_sqe` structs. Without the shift, big SQE rings would index at half the correct offset and two submissions would collide in the same 128 bytes. Makes sense.

**`&sq->sqes[...]`** takes the address of that slot in the SQE array. This is the pointer we get back, the blank form we fill out with our operation details. Next we advance the tail:
```c
sq->sqe_tail = tail + 1;
```

Claim this slot by moving the tail forward by one. The slot is now ours. Note that this is a **local tail** . it has not been written to the shared ring memory yet. The kernel cannot see this yet. The tail only gets flushed to shared memory when we call `io_uring_submit()`, which is what actually makes the kernel aware of new submissions. Now we clear the slot:
```c
io_uring_initialize_sqe(sqe);
```
![diagram](/assets/images/Pasted image 20260328172225.png)

A call to `io_uring_initialize_sqe` which simply zeroes out all the following fields of `io_uring_sqe`. 
```cpp
IOURINGINLINE void io_uring_initialize_sqe(struct io_uring_sqe *sqe)
	LIBURING_NOEXCEPT
{
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->rw_flags = 0;
	sqe->buf_index = 0;
	sqe->personality = 0;
	sqe->file_index = 0;
	sqe->addr3 = 0;
	sqe->__pad2[0] = 0;
}
```
so now we have a fresh object of `io_uring_sqe`.
We then return the same `sqe` back to our main function. moving on in our code..
```cpp
    io_uring_prep_read(sqe, fd, buf, sizeof(buf), 0);
```
![diagram](/assets/images/Pasted image 20260328172753.png){: style="display:block; margin:auto;" }

lets take a look at the function parameter:
```cpp
IOURINGINLINE void io_uring_prep_read(struct io_uring_sqe *sqe, int fd,
void *buf, unsigned nbytes, __u64 offset) LIBURING_NOEXCEPT
{
	io_uring_prep_rw(IORING_OP_READ, sqe, fd, buf, nbytes, offset);
}
```
taking a look at the arguments:

![diagram](/assets/images/Pasted image 20260324194137.png)

from `io_uring_prep_read` we go on to `io_uring_prep_rw` with the following arguments:

![diagram](/assets/images/Pasted image 20260324204547.png)

![diagram](/assets/images/Pasted image 20260328173148.png)

taking a look at our function definition:
```cpp
IOURINGINLINE void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd, const void *addr, unsigned len, __u64 offset) LIBURING_NOEXCEPT
{
sqe->opcode = (__u8) op;
sqe->fd = fd;
sqe->off = offset;
sqe->addr = (unsigned long) addr;
sqe->len = len;
}
```
now if we see what our new fields are set as, they are:

![diagram](/assets/images/Pasted image 20260324205023.png)

We know that `addr` is actually the address of our buffer, `opcode` is `IORING_OP_READ` which is `0x16`. `len` is `0x1000` since we set length of the buffer as `4096`. `sqe->fd` is the file descriptor of our `file.txt` and `sqe->off` is the offset in the file from where we'll start reading. We finally return to our `main` function. 
Now lets finally submit what we've been prepping from now using...
```cpp
    io_uring_submit(&ring);
```
This function submits requests to the submission queue. It fires one syscall, and can batch many SQEs. `io_uring_submit()` calls `__io_uring_submit_and_wait()` .
```cpp
int io_uring_submit(struct io_uring *ring)
{
	return __io_uring_submit_and_wait(ring, 0);
}
```
where ring is of course our `io_uring` object, and 0 are our `wait_nr`. `wait_nr` is the number of completions we want to wait for before the call returns. `wait_nr = 0` means submit and return immediately without waiting for anything. Fire and forget. We will collect completions later ourselves.
```cpp
static int __io_uring_submit_and_wait(struct io_uring *ring, unsigned wait_nr)
{
return __io_uring_submit(ring, __io_uring_flush_sq(ring), wait_nr);
}
```
we'll zoom into `__io_uring_flush_sq first`.  It moves our prepared SQEs into the actual shared submission ring so the kernel can see them.
### `__io_uring_flush_sq` 

![diagram](/assets/images/Pasted image 20260328173630.png)

We first grab the local tail which is the number that has been advancing every time we called `io_uring_get_sqe`.
```c
unsigned tail = sq->sqe_tail;
```
 This represents how many `SQEs` we have prepared in total.

![diagram](/assets/images/Pasted image 20260324232639.png)

The SQ_REWIND special case....
```c
if (ring->flags & IORING_SETUP_SQ_REWIND) {
    sq->sqe_tail = 0;
    return tail;
}
```

`IORING_SETUP_SQ_REWIND` is a special mode where instead of the kernel consuming `SQEs` from wherever the head and tail say, it always starts from the beginning of the `SQE` array on every submission. Like a rewinding a tape where every submit starts from slot 0 again. In this just reset the local tail back to zero so the next round of `io_uring_get_sqe` calls start filling from slot 0 again, and return how many entries were prepared this round. No tail pointer update needed because the kernel ignores head and tail entirely in this mode.  Since `IORING_SETUP_SQ_REWIND` is not set, so we'll skip the conditional statement.

Following is the path we will follow:
```c
if (sq->sqe_head != tail) {
    sq->sqe_head = tail;
```

If `sqe_head` already equals `tail`, nothing new was prepared since the last flush so skip everything, otherwise advance `sqe_head` to match `tail`, which marks all prepared SQEs as flushed.

![diagram](/assets/images/Pasted image 20260324232858.png)

 and after the assignment
 
 ![diagram](/assets/images/Pasted image 20260324232932.png)
 
 next we have...
```c
if (!(ring->flags & IORING_SETUP_SQPOLL))
    *sq->ktail = tail;
else
    io_uring_smp_store_release(sq->ktail, tail);
```
This writes the new tail into shared memory, the moment the kernel sees new work exists. But notice there are two different ways of doing it:

Without `SQPOLL` there's a plain direct write `*sq->ktail = tail`. This is safe because in `non-SQPOLL` mode only your process ever writes to the tail. A plain write is fine and slightly faster.

With `SQPOLL` a dedicated kernel thread is watching the ring continuously. That thread could be reading the tail at the exact same moment we are writing it. The atomic release store prevents any possibility of the kernel seeing a half written value or seeing the tail update before our `SQE` writes are complete.
Here, since `IORING_SETUP_SQPOLL` is not set, the if condition will evaluate as true, and our `ktail` will become equal to 1, as is our tail variable.

![diagram](/assets/images/Pasted image 20260324233211.png)

```c
return tail - IO_URING_READ_ONCE(*sq->khead);
```

Returns how many `SQEs` are currently in the ring waiting to be consumed. The difference is the outstanding workload. `IO_URING_READ_ONCE` is used here because in `SQPOLL` mode the kernel thread could be advancing `khead` right now as it consumes entries. A plain read could get a torn or cached value. `READ_ONCE` forces a single atomic read from the actual memory location.

Back in our `__io_uring_submit_and_wait`. 

![diagram](/assets/images/Pasted image 20260324233332.png)

we see the return value is 1.
so now we make the following call:
```cpp
__io_uring_submit(ring, 1, wait_nr, false);
```
![diagram](/assets/images/Pasted image 20260328174106.png)

In `__io_uring_submit` we do:
```cpp
 bool cq_needs_enter = getevents || wait_nr || cq_ring_needs_enter(ring);
```
`getevents` is what we passed as false. `getevents = false` means "I do not want to collect completions right now. Just submit my `SQE` and return. `wait_nr` too is `0x0`, means we aren't blocking until the arrival of completions. now lets zoom into `cq_ring_needs_enter(ring)`. 
```cpp
static inline bool cq_ring_needs_enter(struct io_uring *ring)
{
return (ring->int_flags & INT_FLAG_CQ_ENTER)||cq_ring_needs_flush(ring);
}
```
we never set `INT_FLAG_CQ_ENTER`. So the first part will evaluate as 0. peeking into `cq_ring_needs_flush`:
```cpp
static inline bool cq_ring_needs_flush(struct io_uring *ring)
{
return IO_URING_READ_ONCE(*ring->sq.kflags) & (IORING_SQ_CQ_OVERFLOW | IORING_SQ_TASKRUN);
}
```
![diagram](/assets/images/Pasted image 20260328174342.png)

recall that we never set `IORING_SQ_TASKRUN` and `IORING_SQ_CQ_OVERFLOW`. Checking it in GDB:

![diagram](/assets/images/Pasted image 20260325193833.png)

so we'll return false from `cq_ring_needs_flush` and `cq_ring_needs_enter` will return:
```cpp
return (0 || 0);
```
Back to `__io_uring_submit`checking return value of `cq_ring_needs_enter` which was being used in `__io_uring_submit`:

![diagram](/assets/images/Pasted image 20260325194506.png)

the following line of code `__io_uring_submit`:
```cpp
 bool cq_needs_enter = getevents || wait_nr || cq_ring_needs_enter(ring);
```
will evaluate as:
```cpp
 bool cq_needs_enter = 0 || 0 || 0;
```
checking it in gdb:

![diagram](/assets/images/Pasted image 20260325194643.png)

`cq_needs_enter = 0`  no syscall is needed for completions at this point. `getevents` was false, `wait_nr` was zero, and `kflags` had no overflow or pending task work. This submit call is purely about getting the `SQE` to the kernel, collecting the completion is handled separately later by `io_uring_wait_cqe`.
Then we do:
```cpp
unsigned flags = ring_enter_flags(ring);
```
![diagram](/assets/images/Pasted image 20260328180512.png)

and seeing `ring_enter_flags`:
```cpp
static inline int ring_enter_flags(struct io_uring *ring)
{
	return ring->int_flags & INT_FLAGS_MASK;
}
```
which again returns 0 since we never set `INT_FLAGS_MASK` meaning no special flags are needed for the `io_uring_enter` syscall.

![diagram](/assets/images/Pasted image 20260325195257.png)

We then return and call `sq_ring_needs_enter` from `__io_uring_submit`. This function answers one question: **does the kernel need to be woken up to process our submissions?**
In `sq_ring_needs_enter` we make the following check:
```c
if (!submit)
    return false;
```

If there are zero `SQEs` to submit, there is nothing to tell the kernel. No syscall needed so we return false.
```c
if (!(ring->flags & IORING_SETUP_SQPOLL))
    return true;
```
If `SQPOLL` is not active the kernel is asleep and has no idea that new `SQEs` exist. A syscall is always required to wake it up so return true. In our case `flags = 0x0` meaning `SQPOLL` is not set. So this line returns true right here and the rest of the function `sq_ring_needs_enter` never runs. This check:
```cpp
if (sq_ring_needs_enter(ring, submitted, &flags) || cq_needs_enter) 
```
 evaluates to
 ```cpp
 if (1 || 0) --> True
 ```
 which means we make the following call in `__io_uring_submit` now:
```cpp
__sys_io_uring_enter(ring->enter_ring_fd, submitted, wait_nr, flags, NULL);
```
and hence we make a syscall, after ample checks of whether or not to make a syscall. After this syscall, we're going to wait for `cqes` via `io_uring_wait_cqe`. 

In our main function we have:
```cpp 
    io_uring_wait_cqe(&ring, &cqe);
```
with the arguments:

![diagram](/assets/images/Pasted image 20260325203427.png)

`rdi` holds our `io_uring` object `ring` of course, and `rsi` holds our `io_uring_cqe` object.
Remember our pizza analogy. We filled out an order form (the `SQE`), handed it to the waiter (`io_uring_submit`), and the kitchen started making our pizza. We are now sitting at the table waiting. `io_uring_wait_cqe` is us looking at the collection counter. From here we're calling `io_uring_wait_cqe_nr`:
```cpp
static inline int io_uring_wait_cqe_nr(struct io_uring *ring, struct io_uring_cqe **cqe_ptr, unsigned wait_nr)
{
return __io_uring_get_cqe(ring, cqe_ptr, 0, wait_nr, NULL);
}
```
with the following arguments:

![diagram](/assets/images/Pasted image 20260325204819.png)

this time `wait_nr` is `0x1`, means we will block until we receive one completion. We further call `__io_uring_get_cqe` with the following arguments:

![diagram](/assets/images/Pasted image 20260325205106.png)

![diagram](/assets/images/Pasted image 20260328181423.png)

This function's only job is to package up everything needed to wait for a completion and pass it down to the actual implementation. The parameters coming in are:
- **`ring`** which is the `io_uring` instance to wait on.

- **`cqe_ptr`** which is a pointer to a pointer. When the function returns, this will point at the `CQE` that just completed which is our read result. This is how the completion event gets handed back to us.

- **`submit`** which in our case this is `0x0`. We already submitted our `SQE` separately via `io_uring_submit`. We aren't submitting anything new here, just waiting.

- **`wait_nr`** is `0x1` which means that block until at least one completion.
- **`sigmask`** is `NULL` in our case. 
So now these get packed into `get_data`:
```c
struct get_data data = {
    .submit    = 0,      //no new submissions
    .wait_nr   = 1,      //block until 1 completion arrives
    .get_flags = 0,      //no extra flags
    .sz        = _NSIG/8 //size of signal mask in bytes
    .arg       = NULL,   //no signal mask
};
```

Then handed straight to `_io_uring_get_cqe` which does the actual work of checking the `CQ` ring and making the syscall if needed..

![diagram](/assets/images/Pasted image 20260325210103.png)

Then we call `__io_uring_get_cqe`:

![diagram](/assets/images/Pasted image 20260328182813.png)

`_io_uring_get_cqe` is the actual wait loop. This is the heart of the completion side. It loops until it either finds a `CQE` or gives up with an error. Every iteration starts by peeking at the `CQ` ring:
```c
ret = __io_uring_peek_cqe(ring, &cqe, &nr_available);
```

This checks if a completed `CQE` is already sitting in the `CQ` ring right now without making any syscall. Like walking to the pizza counter and checking if your order is there. `nr_available` tells us how many completions are currently sitting in the ring. If no `CQE` found and nothing to wait for:
```c
if (!cqe && !data->wait_nr && !data->submit) {
    if (looped || !cq_ring_needs_enter(ring)) {
        err = -EAGAIN;
        break;
    }
}
```

No pizza, no outstanding order, no reason to wait. If we already looped once or the ring needs no flushing, give up and return `-EAGAIN`. If we need more completions than are currently available:
```c
if (data->wait_nr > nr_available || need_enter) {
    flags |= IORING_ENTER_GETEVENTS;
    need_enter = true;
}
```

We asked to wait for `wait_nr` completions but only `nr_available` are ready right now. Not enough pizzas on the counter yet. Mark that we need to enter the kernel and wait for more. If no enter needed at all:
```c
if (!need_enter)
    break;
```

A `CQE` was already waiting in the ring from the peek. Grab it and leave immediately. No syscall needed. Then we make a timeout check
```c
if (looped && data->has_ts) {
    if (!cqe && arg->ts && !err)
        err = -ETIME;
    break;
}
```

If a timeout was specified and we already looped once through the kernel and still have no CQE, we return `-ETIME`. We waited long enough... and the pizza is not coming in time. Then comes the actual syscall:
```c
ret = __sys_io_uring_enter2(ring->enter_ring_fd, data->submit,
                            data->wait_nr, flags, data->arg, data->sz);
```

This is the moment our process goes to sleep. The kernel takes over, processes any pending submissions, waits until `wait_nr` completions are ready, and then wakes us up. When this returns, the CQE SHOULD be in the ring.

**After the syscall:**
```c
data->submit -= ret;
if (cqe)
    break;
if (!looped) {
    looped = true;
    err = ret;
}
```

We subtract how many SQEs were successfully submitted. If a CQE appeared, break out and return it. Set `looped = true` so the next iteration knows we already went through the kernel once. And how do we peek using \_\_io_uring_peek_cqe?

### `__io_uring_peek_cqe` — checking the pizza counter

![diagram](/assets/images/Pasted image 20260328183742.png)

This function looks into the `CQ` ring without making any syscall. Pure memory reads. It is the "walk to the counter and check" step before deciding whether to go to sleep and wait. We load the head and tail atomically:
```c
unsigned tail = io_uring_smp_load_acquire(ring->cq.ktail);
unsigned head = io_uring_smp_load_acquire(ring->cq.khead);
```

Both loaded with acquire semantics. Remember from our ring setup:

- `ktail` which is owned by the kernel. It advances every time the kernel drops a new completion into the ring.
- `khead` is owned by us. It advances every time we consume a completion.

![diagram](/assets/images/anutl.gif){: style="display:block; margin:auto;" }

We then check if anything is available:
```c
available = tail - head;
if (!available)
    break;
```

Same arithmetic as the SQ side but reversed. Here the kernel is the producer advancing tail, and we are the consumer advancing head. If `tail == head` the ring is empty and no completions waiting. We then find the actual `CQE`:
```c
cqe = &ring->cq.cqes[(head & mask) << shift];
```

This is exactly the same pattern as finding an `SQE` slot. `head & mask` wraps the ever increasing head counter into an actual array index. The shift handles `CQE 32` mode where each entry is 32 bytes instead of 16. The result is a pointer directly into the shared `CQ` ring memory where the kernel wrote our completion, and then we do:
```c
if (!io_uring_skip_cqe(ring, cqe, &err))
    break;
cqe = NULL;
```

Some `CQEs` are internal bookkeeping events that our application should never see, things like internal notifications the kernel sends to itself through the ring. `io_uring_skip_cqe` checks if this `CQE` is one of those. If it is, discard it, advance past it, and loop again looking for a real one. If it is a real `CQE` for our application, break out and return it.
```c
*cqe_ptr = cqe;
*nr_available = available;
return err;
```

Hand back the `CQE` pointer and how many completions were available. If `cqe` is not `NULL`, a real completion was found and the caller can read `cqe->res` for the result of the operation. 

From a very high overview, we have the following picture right now:

![diagram](/assets/images/highoverview.png)

Now if we put it all together....

First lets get the address of `sqe array`

![diagram](/assets/images/Pasted image 20260325222533.png)

now we'll get the first slot:

![diagram](/assets/images/Pasted image 20260325222609.png)

Even if we do `p ring.sq.sqes[0]` in GDB, even that would give us the same thing. However if I do `p ring.sq.sqes[1]` or `p ring.sq.sqes[31]` even that will show me zeroed out memory because recall, we allocated 32 slots in the very beginning. Perfect. So:

![diagram](/assets/images/Pasted image 20260325223603.png)

- `pad[0]` = `0x1f`  = `31`   which is the `ring_mask` (31 in binary = 00011111, used for wrapping)
- `pad[1]` = `0x20`  = `32`   are `ring_entries`. We have 32 `SQE` slots total
- `pad[2]` = `0x800` = `2048`  is `sqes_sz`, `32` slots × `64` bytes each = `2048` bytes
- `pad[3]` = `0x0`  is unused padding

one thing to observe is that...

![diagram](/assets/images/Pasted image 20260325224407.png)

`0x2a` is `42` in decimal. That is the tag we set in our code:
```c
sqe->user_data = 42;
```
`42` in hex is `0x2a`. Exact match.

This confirms that the `SQE` we are looking at in memory is exactly the one our program filled out. When the kernel finishes our read and writes a `CQE`, it will copy this `0x2a` straight into `cqe->user_data` unchanged, so when we call `io_uring_wait_cqe` and get the completion back, we can check `cqe->user_data == 42` to confirm this completion belongs to our read request and not some other operation.

This we see is our buffer's address:

![diagram](/assets/images/Pasted image 20260325224851.png)

### taking a lot at `cqes`!
This is the address of our `cq array`

![diagram](/assets/images/Pasted image 20260325224934.png)

this is our first slot:

![diagram](/assets/images/Pasted image 20260325225018.png)

the following gives us a count of the total number of bytes read

![diagram](/assets/images/Pasted image 20260325225111.png)

which are `13`.  and here i again get the same tag back:

![diagram](/assets/images/Pasted image 20260325225158.png)

If we take a look at our heads and tails:
Our kernel consumed up till here

![diagram](/assets/images/Pasted image 20260325225224.png)

and the kernel sees up till here

![diagram](/assets/images/Pasted image 20260325225242.png)

we consumed up till here

![diagram](/assets/images/Pasted image 20260325225313.png)

and the kernel wrote up till here

![diagram](/assets/images/Pasted image 20260325225330.png)

and here comes our actual data!

![diagram](/assets/images/Pasted image 20260325225404.png)

in `io_uring_cqe_seen` we mark the `cqe` as consumed. 
note that we pass the ring object and our `cqe` as arguments:

![diagram](/assets/images/Pasted image 20260325225553.png)

if we dissect it open:
```cpp
IOURINGINLINE void io_uring_cqe_seen(struct io_uring *ring, struct io_uring_cqe *cqe)
LIBURING_NOEXCEPT
{
if (cqe)
io_uring_cq_advance(ring, io_uring_cqe_nr(cqe));
}
```
and since our `cqe` does exist

![diagram](/assets/images/Pasted image 20260325225747.png)

we trigger `io_uring_cq_advance` with these arguments:

![diagram](/assets/images/Pasted image 20260325225948.png)

```cpp
IOURINGINLINE void io_uring_cq_advance(struct io_uring *ring, unsigned nr)
LIBURING_NOEXCEPT
```
This function is called by `io_uring_cqe_seen` after we finish reading a `CQE`. Its job is to advance the `CQ` head pointer to tell the kernel "I have consumed `nr` completions, those slots are free again." In `io_uring_cq_advance` we check if our `nr` does exist, which it does since it's `0x1`, and then do:
```cpp
if (nr) {
struct io_uring_cq *cq = &ring->cq;
```
Only do anything if we are actually consuming at least one `CQE`. If `nr = 0` there is nothing to advance.
```c
io_uring_smp_store_release(cq->khead, *cq->khead + nr);
```

This is the mirror image of the flush store release we saw on the submission side. It writes the new head value into shared memory atomically. The release store says "everything I read from this `CQE` is done now and only now can the kernel see that this slot is free."

In our specific case after `io_uring_cqe_seen`:

```
before: *cq->khead = 0, *cq->ktail = 1   ← 1 completion sitting there
after:  *cq->khead = 1, *cq->ktail = 1   ← ring empty, slot free
```

`khead == ktail` means the `CQ` ring is completely empty and all `64` slots are available for the kernel to write new completions into.
and now if we see `khead`:

![diagram](/assets/images/Pasted image 20260325230634.png)

so its `0x1`...
