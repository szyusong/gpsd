#ifndef _PT_TIMER_H_
#define _PT_TIMER_H_

#include <stdint.h>

typedef struct _pt_timer_t {
  struct _pt_timer_t *next;
  volatile uint16_t ms;  // 超时标志。超时时设置为 0
  volatile uint16_t ticks;
} pt_timer_t;

void PTTimerInitPool(pt_timer_t *pool);
void PTTimerStart(pt_timer_t *pool, pt_timer_t *timer, uint16_t ms);
boolean PTTimerIsExpired(pt_timer_t *timer);
void PTTimerStop(pt_timer_t *pool, pt_timer_t *timer);
void PTTimerTick(pt_timer_t *pool);

#endif /* _PT_TIMER_H_ */
