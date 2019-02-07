static __thread void * shadow_stack[ 16384 ] = {};

void ** nwind_get_shadow_stack() {
    return shadow_stack;
}
