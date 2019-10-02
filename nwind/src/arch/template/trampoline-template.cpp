// This is a template from which we generate the basic outline of the trampoline.

extern "C" {

    void __attribute__ ((visibility ("hidden"))) nwind_dummy();
    void __attribute__ ((noreturn, visibility ("hidden"))) nwind_on_ret_trampoline() noexcept;
    void __attribute__ ((visibility ("hidden"))) nwind_on_exception_through_trampoline() noexcept;
    void __attribute__ ((noreturn)) __cxa_rethrow();

    void __attribute__ ((noreturn, visibility ("hidden"))) nwind_ret_trampoline_start() noexcept {
        try {
            nwind_dummy();
            nwind_on_ret_trampoline();
        } catch (...) {
            nwind_on_exception_through_trampoline();
            __cxa_rethrow();
        }
    }

}
