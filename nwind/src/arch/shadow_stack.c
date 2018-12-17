#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>

static __thread void * shadow_stack[ 16384 ] = {};

void ** nwind_get_shadow_stack() {
    return shadow_stack;
}

void nwind_on_raise_exception();

typedef int (*RaiseException)( void * );

int _Unwind_RaiseException( void * ctx ) {
    nwind_on_raise_exception();
    RaiseException raise = dlsym( RTLD_NEXT, "_Unwind_RaiseException" );
    return raise( ctx );
}
