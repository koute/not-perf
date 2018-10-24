static __thread void * shadow_stack[ 1024 ] = {};

void ** nwind_get_shadow_stack() {
    return shadow_stack;
}
