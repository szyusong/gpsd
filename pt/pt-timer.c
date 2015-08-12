
#include "pt-timer.h"

void 
PTTimerTick(pt_timer_t *pool)
{
  timer_t *timer = pool.next;

  if ( timer )
  {
    if ( timer->ticks )
    {
      timer->ticks--;
    }
    if (0 == timer->ticks)
    {
      timer->ms = 0;

      while( timer )  // 将后续超时的定时器都移除
      {
        timer = timer->next;

        if (timer && (0 == timer->ticks))
        {
          timer->ms = 0;
        }
        else
        {
          break;
        }
      }
      pool.next = timer;
    }
  }
}

void 
PTTimerInitPool(pt_timer_t *pool)
{
  pool.ticks = 0;
  pool.next = NULL;
}

void
PTTimerStart(pt_timer_t *pool, timer_t *timer, uint16_t ms)
{
  timer_t *p = pool;

  PTTimerStop(pool, timer);
  
  timer->next = NULL;
  timer->ms = ms;
  timer->ticks = _ms(ms);

  if (0 == ms) return;

  while( p->next )
  {
    if (timer->ticks < p->next->ticks)
    {
      p->next->ticks -= timer->ticks;
      timer->next = p->next;
      p->next = timer;
      break;
    }
    else
    {
      timer->ticks -= p->next->ticks;  // timer->ticks 有可能为 0
    }
    p = p->next;
  }
  if (NULL == p->next)
  {
    p->next = timer;
  }
}

boolean 
PTTimerIsExpired(timer_t *timer)
{
  return (0 == timer->ms);
}

void 
PTTimerStop(pt_timer_t *pool, timer_t *timer)
{
  timer_t *p = pool;

  if (timer && timer->ms)
  {
    while( p->next )
	  {
	    if (p->next == timer)
	    {
	      if ( timer->next )
	      {
	        timer->next->ticks += timer->ticks;
	      }
	      p->next = timer->next;
	      timer->ms = 0;
	      timer->next = NULL;
	      break; 
	    }
	    p = p->next;
	  }
  }
}

