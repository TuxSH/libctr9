/*******************************************************************************
 * Copyright (C) 2016 Gabriel Marcano
 *
 * Refer to the COPYING.txt file at the top of the project directory. If that is
 * missing, this file is licensed under the GPL version 2.0 or later.
 *
 ******************************************************************************/

#include <ctr9/ctr_timer.h>
#include <ctr9/ctr_irq.h>
#include <ctr9/ctr_system_clock.h>

#include <stddef.h>

void ctr_system_clock_interrupt_0(void);
void ctr_system_clock_interrupt_1(void);
void ctr_system_clock_interrupt_2(void);
void ctr_system_clock_interrupt_3(void);

static void (*interrupts[4])(void) =
{
	ctr_system_clock_interrupt_0,
	ctr_system_clock_interrupt_1,
	ctr_system_clock_interrupt_2,
	ctr_system_clock_interrupt_3
};

static unsigned int active_clocks = 0;

static ctr_system_clock *clocks[4]  = { NULL };

void ctr_system_clock_initialize(ctr_system_clock *clock, ctr_timer timer)
{
	clock->count = 0;
	if (timer < 4u)
	{
		ctr_irq_disable(CTR_IRQ_TIMER_0 + timer);

		ctr_timer_disable(timer);
		ctr_timer_disable_irq(timer);
		ctr_irq_acknowledge(CTR_IRQ_TIMER_0 + timer);

		ctr_timer_set_value(timer, 0);
		ctr_timer_set_prescaler(timer, CTR_TIMER_DIV1);
		clocks[timer] = clock;
		ctr_irq_register(CTR_IRQ_TIMER_0 + timer, interrupts[timer]);
		clock->timer = timer;
		clock->count = 0;

		active_clocks |= 1u << timer;

		ctr_timer_enable_irq(timer);
		ctr_timer_enable(timer);
		ctr_irq_enable(CTR_IRQ_TIMER_0 + timer);
	}
}

uint64_t ctr_system_clock_get_ms(ctr_system_clock *clock)
{
	ctr_irq_critical_enter();
	uint64_t timestamp = clock->count;
	ctr_irq_critical_leave();

	uint32_t freq = ctr_timer_get_effective_frequency(clock->timer);
	return timestamp * 1000u / (freq / (1u << 16)) ;
}

ctr_clock_time ctr_system_clock_get_time(ctr_system_clock *clock)
{
	ctr_irq_critical_enter();
	uint64_t timestamp = clock->count;
	ctr_irq_critical_leave();

	uint32_t freq = ctr_timer_get_effective_frequency(clock->timer);
	ctr_clock_time result;
	uint32_t period = freq / (1u << 16);
	result.seconds = (int64_t)timestamp / period ;
	result.nanoseconds = ((uint64_t)timestamp - (uint64_t)result.seconds * period) * 1000000000u / period;
	return result;
}

static inline void ctr_system_clock_interrupt(ctr_timer timer)
{
	if ((timer < 4u) && (active_clocks & (1u << timer)))
	{
		clocks[timer]->count += 1u;
	}
	ctr_irq_acknowledge(CTR_IRQ_TIMER_0 + timer);
}

#define DEFINE_CTR_SYSTEM_CLOCK_INTERRUPT(N) \
void ctr_system_clock_interrupt_##N(void) \
{ \
	ctr_system_clock_interrupt(N); \
}

DEFINE_CTR_SYSTEM_CLOCK_INTERRUPT(0)
DEFINE_CTR_SYSTEM_CLOCK_INTERRUPT(1)
DEFINE_CTR_SYSTEM_CLOCK_INTERRUPT(2)
DEFINE_CTR_SYSTEM_CLOCK_INTERRUPT(3)

