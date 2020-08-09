#pragma once

// declaration for SOS functions and structs. We will be linked against the SOS binary,
// therefore we will have access to these functions.

typedef int (*sos_irq_callback_t)(
    void *data,
    seL4_Word irq,
    seL4_IRQHandler irq_handler
);


int sos_register_irq_handler(seL4_Word irq, bool edge_triggered, 
    sos_irq_callback_t callback, void *data, seL4_IRQHandler *irq_handler);

void delegate_fake_timer_tick();
