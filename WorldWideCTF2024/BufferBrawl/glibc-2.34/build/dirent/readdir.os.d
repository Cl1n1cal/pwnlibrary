$(common-objpfx)dirent/readdir.os: \
 ../sysdeps/unix/sysv/linux/readdir.c ../include/stdc-predef.h \
 $(common-objpfx)libc-modules.h \
 ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/generic/libc-symver.h ../sysdeps/generic/symbol-hacks.h \
 ../include/dirent.h ../sysdeps/unix/sysv/linux/dirstream.h \
 ../include/sys/types.h ../posix/sys/types.h ../include/features.h \
 ../include/features-time64.h \
 ../sysdeps/unix/sysv/linux/features-time64.h \
 ../sysdeps/x86/bits/wordsize.h \
 ../sysdeps/unix/sysv/linux/x86/bits/timesize.h ../include/sys/cdefs.h \
 ../misc/sys/cdefs.h ../sysdeps/ieee754/ldbl-96/bits/long-double.h \
 ../include/gnu/stubs.h ../include/bits/types.h ../posix/bits/types.h \
 ../sysdeps/unix/sysv/linux/x86/bits/typesizes.h ../bits/time64.h \
 ../include/bits/types/clock_t.h ../time/bits/types/clock_t.h \
 ../include/bits/types/clockid_t.h ../time/bits/types/clockid_t.h \
 ../include/bits/types/time_t.h ../time/bits/types/time_t.h \
 ../include/bits/types/timer_t.h ../time/bits/types/timer_t.h \
 /usr/lib/gcc/x86_64-linux-gnu/9/include/stddef.h ../bits/stdint-intn.h \
 ../include/endian.h ../string/endian.h ../include/bits/endian.h \
 ../string/bits/endian.h ../sysdeps/x86/bits/endianness.h \
 ../bits/byteswap.h ../bits/uintn-identity.h ../include/sys/select.h \
 ../misc/sys/select.h ../bits/select.h ../include/bits/types/sigset_t.h \
 ../signal/bits/types/sigset_t.h \
 ../sysdeps/unix/sysv/linux/bits/types/__sigset_t.h \
 ../include/bits/types/struct_timeval.h \
 ../time/bits/types/struct_timeval.h \
 ../include/bits/types/struct_timespec.h \
 ../time/bits/types/struct_timespec.h ../sysdeps/nptl/bits/pthreadtypes.h \
 ../sysdeps/nptl/bits/thread-shared-types.h \
 ../sysdeps/x86/nptl/bits/pthreadtypes-arch.h \
 ../sysdeps/x86/nptl/bits/struct_mutex.h \
 ../sysdeps/x86/nptl/bits/struct_rwlock.h ../sysdeps/nptl/libc-lock.h \
 ../include/pthread.h ../sysdeps/nptl/pthread.h ../include/sched.h \
 ../posix/sched.h ../sysdeps/unix/sysv/linux/bits/sched.h \
 ../bits/types/struct_sched_param.h ../include/bits/cpu-set.h \
 ../posix/bits/cpu-set.h ../include/time.h ../time/time.h \
 ../sysdeps/unix/sysv/linux/bits/time.h \
 ../sysdeps/unix/sysv/linux/bits/timex.h \
 ../include/bits/types/struct_tm.h ../time/bits/types/struct_tm.h \
 ../include/bits/types/struct_itimerspec.h \
 ../time/bits/types/struct_itimerspec.h ../include/bits/types/locale_t.h \
 ../locale/bits/types/locale_t.h ../include/bits/types/__locale_t.h \
 ../locale/bits/types/__locale_t.h ../include/struct___timespec64.h \
 ../include/struct___timeval64.h \
 /usr/lib/gcc/x86_64-linux-gnu/9/include/stdbool.h \
 ../time/mktime-internal.h ../include/sys/time.h ../time/sys/time.h \
 ../sysdeps/unix/sysv/linux/time-clockid.h ../sysdeps/x86/bits/setjmp.h \
 ../include/bits/types/struct___jmp_buf_tag.h \
 ../setjmp/bits/types/struct___jmp_buf_tag.h \
 ../sysdeps/unix/sysv/linux/include/bits/pthread_stack_min-dynamic.h \
 ../sysdeps/unix/sysv/linux/bits/pthread_stack_min.h \
 ../sysdeps/nptl/libc-lockP.h ../sysdeps/nptl/lowlevellock.h \
 ../include/atomic.h ../include/stdlib.h ../sysdeps/x86/bits/floatn.h \
 ../bits/floatn-common.h ../stdlib/stdlib.h ../bits/libc-header-start.h \
 ../sysdeps/unix/sysv/linux/bits/waitflags.h ../bits/waitstatus.h \
 ../include/alloca.h ../stdlib/alloca.h ../include/stackinfo.h \
 ../sysdeps/x86_64/stackinfo.h ../include/elf.h ../elf/elf.h \
 ../include/stdint.h ../stdlib/stdint.h ../bits/wchar.h \
 ../bits/stdint-uintn.h ../include/libc-pointer-arith.h \
 ../sysdeps/generic/dl-dtprocnum.h ../sysdeps/pthread/allocalim.h \
 ../include/limits.h /usr/lib/gcc/x86_64-linux-gnu/9/include/limits.h \
 ../include/bits/posix1_lim.h ../posix/bits/posix1_lim.h \
 ../sysdeps/unix/sysv/linux/bits/local_lim.h /usr/include/linux/limits.h \
 ../include/bits/posix2_lim.h ../posix/bits/posix2_lim.h \
 ../include/bits/xopen_lim.h ../sysdeps/unix/sysv/linux/bits/uio_lim.h \
 ../bits/stdlib-bsearch.h ../include/bits/stdlib-float.h \
 ../stdlib/bits/stdlib-float.h ../include/sys/stat.h ../io/sys/stat.h \
 ../sysdeps/unix/sysv/linux/bits/stat.h \
 ../sysdeps/unix/sysv/linux/x86/bits/struct_stat.h \
 ../include/bits/statx.h ../io/bits/statx.h \
 ../include/bits/statx-generic.h ../io/bits/statx-generic.h \
 ../include/bits/types/struct_statx_timestamp.h \
 ../io/bits/types/struct_statx_timestamp.h \
 ../include/bits/types/struct_statx.h ../io/bits/types/struct_statx.h \
 ../sysdeps/unix/sysv/linux/x86/xstatver.h \
 ../sysdeps/unix/sysv/linux/struct_stat_time64.h ../include/rtld-malloc.h \
 ../sysdeps/x86/atomic-machine.h ../sysdeps/x86_64/nptl/tls.h \
 ../sysdeps/unix/sysv/linux/x86/include/asm/prctl.h \
 /usr/include/x86_64-linux-gnu/asm/prctl.h \
 ../sysdeps/unix/sysv/linux/x86_64/sysdep.h \
 ../sysdeps/unix/sysv/linux/sysdep.h \
 ../sysdeps/unix/sysv/linux/x86_64/kernel-features.h \
 ../sysdeps/unix/sysv/linux/kernel-features.h ../include/errno.h \
 ../stdlib/errno.h ../sysdeps/unix/sysv/linux/bits/errno.h \
 /usr/include/linux/errno.h /usr/include/x86_64-linux-gnu/asm/errno.h \
 /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h \
 ../bits/types/error_t.h ../sysdeps/unix/x86_64/sysdep.h \
 ../sysdeps/unix/sysdep.h ../sysdeps/generic/sysdep.h \
 ../sysdeps/generic/dwarf2.h ../sysdeps/unix/sysv/linux/single-thread.h \
 ../sysdeps/unix/sysv/linux/include/sys/syscall.h \
 ../sysdeps/unix/sysv/linux/x86_64/64/arch-syscall.h \
 ../sysdeps/x86_64/sysdep.h ../sysdeps/x86/sysdep.h \
 ../sysdeps/unix/sysv/linux/dl-sysdep.h ../sysdeps/generic/dl-sysdep.h \
 ../sysdeps/generic/dl-dtv.h ../nptl/descr.h ../include/setjmp.h \
 ../setjmp/setjmp.h ../sysdeps/unix/sysv/linux/x86_64/64/jmp_buf-macros.h \
 ../sysdeps/x86/hp-timing.h ../sysdeps/x86_64/isa.h \
 ../sysdeps/generic/hp-timing-common.h ../include/string.h \
 ../include/locale.h ../locale/locale.h ../include/bits/locale.h \
 ../locale/bits/locale.h ../sysdeps/x86/string_private.h \
 ../string/string.h ../include/strings.h ../string/strings.h \
 ../include/sys/param.h ../misc/sys/param.h ../include/signal.h \
 ../signal/signal.h ../bits/signum-generic.h \
 ../sysdeps/unix/sysv/linux/bits/signum-arch.h \
 ../include/bits/types/sig_atomic_t.h ../signal/bits/types/sig_atomic_t.h \
 ../sysdeps/unix/sysv/linux/bits/types/siginfo_t.h \
 ../include/bits/types/__sigval_t.h ../signal/bits/types/__sigval_t.h \
 ../sysdeps/unix/sysv/linux/x86/bits/siginfo-arch.h \
 ../sysdeps/unix/sysv/linux/bits/siginfo-consts.h \
 ../sysdeps/unix/sysv/linux/bits/siginfo-consts-arch.h \
 ../include/bits/types/sigval_t.h ../signal/bits/types/sigval_t.h \
 ../sysdeps/unix/sysv/linux/bits/types/sigevent_t.h \
 ../sysdeps/unix/sysv/linux/bits/sigevent-consts.h \
 ../sysdeps/unix/sysv/linux/bits/sigaction.h \
 ../sysdeps/unix/sysv/linux/x86/bits/sigcontext.h \
 ../sysdeps/unix/sysv/linux/bits/types/stack_t.h \
 ../sysdeps/unix/sysv/linux/x86/sys/ucontext.h ../include/bits/sigstack.h \
 ../sysdeps/unix/sysv/linux/x86/include/bits/sigstack.h \
 ../sysdeps/unix/sysv/linux/bits/sigstack.h ../include/bits/sigstksz.h \
 ../sysdeps/unix/sysv/linux/bits/ss_flags.h \
 ../include/bits/types/struct_sigstack.h \
 ../signal/bits/types/struct_sigstack.h \
 ../sysdeps/pthread/bits/sigthread.h \
 ../sysdeps/unix/sysv/linux/bits/signal_ext.h \
 ../sysdeps/unix/sysv/linux/sigsetops.h \
 ../sysdeps/unix/sysv/linux/bits/param.h /usr/include/linux/param.h \
 /usr/include/x86_64-linux-gnu/asm/param.h \
 /usr/include/asm-generic/param.h ../sysdeps/generic/_itoa.h \
 ../include/list_t.h ../sysdeps/x86/nptl/pthreaddef.h \
 ../sysdeps/nptl/thread_db.h ../sysdeps/unix/sysv/linux/sys/procfs.h \
 ../sysdeps/unix/sysv/linux/x86/sys/user.h \
 ../sysdeps/unix/sysv/linux/x86/bits/procfs.h \
 ../sysdeps/unix/sysv/linux/x86/bits/procfs-id.h \
 ../sysdeps/unix/sysv/linux/bits/procfs-prregset.h \
 ../sysdeps/unix/sysv/linux/bits/procfs-extra.h \
 ../sysdeps/generic/unwind.h ../include/bits/types/res_state.h \
 ../resolv/bits/types/res_state.h ../include/netinet/in.h \
 ../inet/netinet/in.h ../include/sys/socket.h ../socket/sys/socket.h \
 ../include/bits/types/struct_iovec.h ../misc/bits/types/struct_iovec.h \
 ../sysdeps/unix/sysv/linux/bits/socket.h \
 ../sysdeps/unix/sysv/linux/bits/socket_type.h ../bits/sockaddr.h \
 /usr/include/x86_64-linux-gnu/asm/socket.h \
 /usr/include/asm-generic/socket.h /usr/include/linux/posix_types.h \
 /usr/include/linux/stddef.h \
 /usr/include/x86_64-linux-gnu/asm/posix_types.h \
 /usr/include/x86_64-linux-gnu/asm/posix_types_64.h \
 /usr/include/asm-generic/posix_types.h \
 /usr/include/x86_64-linux-gnu/asm/bitsperlong.h \
 /usr/include/asm-generic/bitsperlong.h \
 /usr/include/x86_64-linux-gnu/asm/sockios.h \
 /usr/include/asm-generic/sockios.h \
 ../include/bits/types/struct_osockaddr.h \
 ../socket/bits/types/struct_osockaddr.h \
 ../sysdeps/unix/sysv/linux/bits/in.h \
 ../sysdeps/generic/tls-internal-struct.h \
 ../sysdeps/unix/sysv/linux/x86/elision-conf.h \
 ../sysdeps/nptl/lowlevellock-futex.h \
 ../sysdeps/unix/sysv/linux/sysdep-cancel.h ../dirent/dirent.h \
 ../sysdeps/unix/sysv/linux/bits/dirent.h \
 ../sysdeps/unix/sysv/linux/bits/dirent_ext.h

../include/stdc-predef.h:

$(common-objpfx)libc-modules.h:

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/generic/libc-symver.h:

../sysdeps/generic/symbol-hacks.h:

../include/dirent.h:

../sysdeps/unix/sysv/linux/dirstream.h:

../include/sys/types.h:

../posix/sys/types.h:

../include/features.h:

../include/features-time64.h:

../sysdeps/unix/sysv/linux/features-time64.h:

../sysdeps/x86/bits/wordsize.h:

../sysdeps/unix/sysv/linux/x86/bits/timesize.h:

../include/sys/cdefs.h:

../misc/sys/cdefs.h:

../sysdeps/ieee754/ldbl-96/bits/long-double.h:

../include/gnu/stubs.h:

../include/bits/types.h:

../posix/bits/types.h:

../sysdeps/unix/sysv/linux/x86/bits/typesizes.h:

../bits/time64.h:

../include/bits/types/clock_t.h:

../time/bits/types/clock_t.h:

../include/bits/types/clockid_t.h:

../time/bits/types/clockid_t.h:

../include/bits/types/time_t.h:

../time/bits/types/time_t.h:

../include/bits/types/timer_t.h:

../time/bits/types/timer_t.h:

/usr/lib/gcc/x86_64-linux-gnu/9/include/stddef.h:

../bits/stdint-intn.h:

../include/endian.h:

../string/endian.h:

../include/bits/endian.h:

../string/bits/endian.h:

../sysdeps/x86/bits/endianness.h:

../bits/byteswap.h:

../bits/uintn-identity.h:

../include/sys/select.h:

../misc/sys/select.h:

../bits/select.h:

../include/bits/types/sigset_t.h:

../signal/bits/types/sigset_t.h:

../sysdeps/unix/sysv/linux/bits/types/__sigset_t.h:

../include/bits/types/struct_timeval.h:

../time/bits/types/struct_timeval.h:

../include/bits/types/struct_timespec.h:

../time/bits/types/struct_timespec.h:

../sysdeps/nptl/bits/pthreadtypes.h:

../sysdeps/nptl/bits/thread-shared-types.h:

../sysdeps/x86/nptl/bits/pthreadtypes-arch.h:

../sysdeps/x86/nptl/bits/struct_mutex.h:

../sysdeps/x86/nptl/bits/struct_rwlock.h:

../sysdeps/nptl/libc-lock.h:

../include/pthread.h:

../sysdeps/nptl/pthread.h:

../include/sched.h:

../posix/sched.h:

../sysdeps/unix/sysv/linux/bits/sched.h:

../bits/types/struct_sched_param.h:

../include/bits/cpu-set.h:

../posix/bits/cpu-set.h:

../include/time.h:

../time/time.h:

../sysdeps/unix/sysv/linux/bits/time.h:

../sysdeps/unix/sysv/linux/bits/timex.h:

../include/bits/types/struct_tm.h:

../time/bits/types/struct_tm.h:

../include/bits/types/struct_itimerspec.h:

../time/bits/types/struct_itimerspec.h:

../include/bits/types/locale_t.h:

../locale/bits/types/locale_t.h:

../include/bits/types/__locale_t.h:

../locale/bits/types/__locale_t.h:

../include/struct___timespec64.h:

../include/struct___timeval64.h:

/usr/lib/gcc/x86_64-linux-gnu/9/include/stdbool.h:

../time/mktime-internal.h:

../include/sys/time.h:

../time/sys/time.h:

../sysdeps/unix/sysv/linux/time-clockid.h:

../sysdeps/x86/bits/setjmp.h:

../include/bits/types/struct___jmp_buf_tag.h:

../setjmp/bits/types/struct___jmp_buf_tag.h:

../sysdeps/unix/sysv/linux/include/bits/pthread_stack_min-dynamic.h:

../sysdeps/unix/sysv/linux/bits/pthread_stack_min.h:

../sysdeps/nptl/libc-lockP.h:

../sysdeps/nptl/lowlevellock.h:

../include/atomic.h:

../include/stdlib.h:

../sysdeps/x86/bits/floatn.h:

../bits/floatn-common.h:

../stdlib/stdlib.h:

../bits/libc-header-start.h:

../sysdeps/unix/sysv/linux/bits/waitflags.h:

../bits/waitstatus.h:

../include/alloca.h:

../stdlib/alloca.h:

../include/stackinfo.h:

../sysdeps/x86_64/stackinfo.h:

../include/elf.h:

../elf/elf.h:

../include/stdint.h:

../stdlib/stdint.h:

../bits/wchar.h:

../bits/stdint-uintn.h:

../include/libc-pointer-arith.h:

../sysdeps/generic/dl-dtprocnum.h:

../sysdeps/pthread/allocalim.h:

../include/limits.h:

/usr/lib/gcc/x86_64-linux-gnu/9/include/limits.h:

../include/bits/posix1_lim.h:

../posix/bits/posix1_lim.h:

../sysdeps/unix/sysv/linux/bits/local_lim.h:

/usr/include/linux/limits.h:

../include/bits/posix2_lim.h:

../posix/bits/posix2_lim.h:

../include/bits/xopen_lim.h:

../sysdeps/unix/sysv/linux/bits/uio_lim.h:

../bits/stdlib-bsearch.h:

../include/bits/stdlib-float.h:

../stdlib/bits/stdlib-float.h:

../include/sys/stat.h:

../io/sys/stat.h:

../sysdeps/unix/sysv/linux/bits/stat.h:

../sysdeps/unix/sysv/linux/x86/bits/struct_stat.h:

../include/bits/statx.h:

../io/bits/statx.h:

../include/bits/statx-generic.h:

../io/bits/statx-generic.h:

../include/bits/types/struct_statx_timestamp.h:

../io/bits/types/struct_statx_timestamp.h:

../include/bits/types/struct_statx.h:

../io/bits/types/struct_statx.h:

../sysdeps/unix/sysv/linux/x86/xstatver.h:

../sysdeps/unix/sysv/linux/struct_stat_time64.h:

../include/rtld-malloc.h:

../sysdeps/x86/atomic-machine.h:

../sysdeps/x86_64/nptl/tls.h:

../sysdeps/unix/sysv/linux/x86/include/asm/prctl.h:

/usr/include/x86_64-linux-gnu/asm/prctl.h:

../sysdeps/unix/sysv/linux/x86_64/sysdep.h:

../sysdeps/unix/sysv/linux/sysdep.h:

../sysdeps/unix/sysv/linux/x86_64/kernel-features.h:

../sysdeps/unix/sysv/linux/kernel-features.h:

../include/errno.h:

../stdlib/errno.h:

../sysdeps/unix/sysv/linux/bits/errno.h:

/usr/include/linux/errno.h:

/usr/include/x86_64-linux-gnu/asm/errno.h:

/usr/include/asm-generic/errno.h:

/usr/include/asm-generic/errno-base.h:

../bits/types/error_t.h:

../sysdeps/unix/x86_64/sysdep.h:

../sysdeps/unix/sysdep.h:

../sysdeps/generic/sysdep.h:

../sysdeps/generic/dwarf2.h:

../sysdeps/unix/sysv/linux/single-thread.h:

../sysdeps/unix/sysv/linux/include/sys/syscall.h:

../sysdeps/unix/sysv/linux/x86_64/64/arch-syscall.h:

../sysdeps/x86_64/sysdep.h:

../sysdeps/x86/sysdep.h:

../sysdeps/unix/sysv/linux/dl-sysdep.h:

../sysdeps/generic/dl-sysdep.h:

../sysdeps/generic/dl-dtv.h:

../nptl/descr.h:

../include/setjmp.h:

../setjmp/setjmp.h:

../sysdeps/unix/sysv/linux/x86_64/64/jmp_buf-macros.h:

../sysdeps/x86/hp-timing.h:

../sysdeps/x86_64/isa.h:

../sysdeps/generic/hp-timing-common.h:

../include/string.h:

../include/locale.h:

../locale/locale.h:

../include/bits/locale.h:

../locale/bits/locale.h:

../sysdeps/x86/string_private.h:

../string/string.h:

../include/strings.h:

../string/strings.h:

../include/sys/param.h:

../misc/sys/param.h:

../include/signal.h:

../signal/signal.h:

../bits/signum-generic.h:

../sysdeps/unix/sysv/linux/bits/signum-arch.h:

../include/bits/types/sig_atomic_t.h:

../signal/bits/types/sig_atomic_t.h:

../sysdeps/unix/sysv/linux/bits/types/siginfo_t.h:

../include/bits/types/__sigval_t.h:

../signal/bits/types/__sigval_t.h:

../sysdeps/unix/sysv/linux/x86/bits/siginfo-arch.h:

../sysdeps/unix/sysv/linux/bits/siginfo-consts.h:

../sysdeps/unix/sysv/linux/bits/siginfo-consts-arch.h:

../include/bits/types/sigval_t.h:

../signal/bits/types/sigval_t.h:

../sysdeps/unix/sysv/linux/bits/types/sigevent_t.h:

../sysdeps/unix/sysv/linux/bits/sigevent-consts.h:

../sysdeps/unix/sysv/linux/bits/sigaction.h:

../sysdeps/unix/sysv/linux/x86/bits/sigcontext.h:

../sysdeps/unix/sysv/linux/bits/types/stack_t.h:

../sysdeps/unix/sysv/linux/x86/sys/ucontext.h:

../include/bits/sigstack.h:

../sysdeps/unix/sysv/linux/x86/include/bits/sigstack.h:

../sysdeps/unix/sysv/linux/bits/sigstack.h:

../include/bits/sigstksz.h:

../sysdeps/unix/sysv/linux/bits/ss_flags.h:

../include/bits/types/struct_sigstack.h:

../signal/bits/types/struct_sigstack.h:

../sysdeps/pthread/bits/sigthread.h:

../sysdeps/unix/sysv/linux/bits/signal_ext.h:

../sysdeps/unix/sysv/linux/sigsetops.h:

../sysdeps/unix/sysv/linux/bits/param.h:

/usr/include/linux/param.h:

/usr/include/x86_64-linux-gnu/asm/param.h:

/usr/include/asm-generic/param.h:

../sysdeps/generic/_itoa.h:

../include/list_t.h:

../sysdeps/x86/nptl/pthreaddef.h:

../sysdeps/nptl/thread_db.h:

../sysdeps/unix/sysv/linux/sys/procfs.h:

../sysdeps/unix/sysv/linux/x86/sys/user.h:

../sysdeps/unix/sysv/linux/x86/bits/procfs.h:

../sysdeps/unix/sysv/linux/x86/bits/procfs-id.h:

../sysdeps/unix/sysv/linux/bits/procfs-prregset.h:

../sysdeps/unix/sysv/linux/bits/procfs-extra.h:

../sysdeps/generic/unwind.h:

../include/bits/types/res_state.h:

../resolv/bits/types/res_state.h:

../include/netinet/in.h:

../inet/netinet/in.h:

../include/sys/socket.h:

../socket/sys/socket.h:

../include/bits/types/struct_iovec.h:

../misc/bits/types/struct_iovec.h:

../sysdeps/unix/sysv/linux/bits/socket.h:

../sysdeps/unix/sysv/linux/bits/socket_type.h:

../bits/sockaddr.h:

/usr/include/x86_64-linux-gnu/asm/socket.h:

/usr/include/asm-generic/socket.h:

/usr/include/linux/posix_types.h:

/usr/include/linux/stddef.h:

/usr/include/x86_64-linux-gnu/asm/posix_types.h:

/usr/include/x86_64-linux-gnu/asm/posix_types_64.h:

/usr/include/asm-generic/posix_types.h:

/usr/include/x86_64-linux-gnu/asm/bitsperlong.h:

/usr/include/asm-generic/bitsperlong.h:

/usr/include/x86_64-linux-gnu/asm/sockios.h:

/usr/include/asm-generic/sockios.h:

../include/bits/types/struct_osockaddr.h:

../socket/bits/types/struct_osockaddr.h:

../sysdeps/unix/sysv/linux/bits/in.h:

../sysdeps/generic/tls-internal-struct.h:

../sysdeps/unix/sysv/linux/x86/elision-conf.h:

../sysdeps/nptl/lowlevellock-futex.h:

../sysdeps/unix/sysv/linux/sysdep-cancel.h:

../dirent/dirent.h:

../sysdeps/unix/sysv/linux/bits/dirent.h:

../sysdeps/unix/sysv/linux/bits/dirent_ext.h:
