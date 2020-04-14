#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>

#include "main.h"

#define CREATE_TIMER 1
#define UPDATE_TIMER 0

extern struct rte_ring *cdr_ring;

typedef struct session {
	uint64_t session_id;
	time_t ts;
	struct session *next;
	struct session *last;
} session_t;



typedef struct apn_timer_struct {
	session_t list_head;
	timer_t timer_id;
	char lock;
	int idx;
	int timer_threshold;
} apn_timer_struct_t;


apn_timer_struct_t apn_timers[MAX_NB_APN] = {{{0,0,NULL,NULL},0,0,0,0},};

static void ats_handler(int sig, siginfo_t *si, void *uc);
static void ats_manage_per_apn_timer(int interval_in_secs, int create_timer, int apn_idx);

long ats_is_apn_timer_initialized(int apn_idx) {
	apn_timer_struct_t *apn_timer_struct = &apn_timers[apn_idx];
	return (long)(apn_timer_struct->timer_id);
}

void ats_init(int timer_threshold, int apn_idx) {
	apn_timer_struct_t *apn_timer_struct = &apn_timers[apn_idx];
	session_t *head = &apn_timer_struct->list_head;
	head->next = NULL;
	head->last = head;
	head->session_id = -1;
	apn_timer_struct->lock = 0;
	apn_timer_struct->idx = apn_idx;
	apn_timer_struct->timer_threshold = timer_threshold;;
	ats_manage_per_apn_timer(0, CREATE_TIMER, apn_idx);//Create the timer, don't start
}


void ats_list_add_to_tail(uint64_t session_id, int apn_idx) {
	apn_timer_struct_t *apn_timer_struct = &apn_timers[apn_idx];
	session_t *head = &apn_timer_struct->list_head;
	session_t* new = malloc(sizeof(session_t));
	if (head->next == NULL) { //Indicates first node add condition
		ats_manage_per_apn_timer(apn_timer_struct->timer_threshold,
				UPDATE_TIMER, apn_idx);
	}
	new->session_id = session_id;
	new->ts = time(NULL);
	new->next = NULL;
	new->last = new;
	apn_timer_struct->lock = 1;
	head->last->next = new;
	head->last = new;
	apn_timer_struct->lock = 0;
}

void ats_list_del_node(uint64_t session_id, int apn_idx) {
	apn_timer_struct_t *apn_timer_struct = &apn_timers[apn_idx];
	session_t *head = &apn_timer_struct->list_head;
	session_t *prev;
	session_t *ptr = head;
	apn_timer_struct->lock = 1;
	do {
		prev = ptr;
		ptr = ptr->next;
	} while ((ptr != NULL) && (ptr->session_id != session_id));
	if (ptr != NULL) {
		prev->next = ptr->next; //Check of for head->last asjustment
		if (prev->next == NULL) { //tail node condition
			head->last = prev;
		}
		if (head->next == NULL) {  //Indicates empty list
			ats_manage_per_apn_timer(0,	UPDATE_TIMER, apn_idx);
		}
		free(ptr);
	}
	apn_timer_struct->lock = 0;
}

void ats_list_move_to_tail(int apn_idx) {
	apn_timer_struct_t *apn_timer_struct = &apn_timers[apn_idx];
	session_t *head = &apn_timer_struct->list_head;
	apn_timer_struct->lock = 1;
	head->last->next = head->next;
	head->next = head->next->next;
	head->last = head->last->next;
	head->last->next = NULL;
	head->last->last = head->last;
	apn_timer_struct->lock = 0;

}

void print_list(session_t *head) {
	session_t *ptr = head;
	printf("\n************************\n");
	while (ptr != NULL) {
		printf("session %ld\n", ptr->session_id);
		ptr = ptr->next;
	}
	printf("************************\n");
}


static void ats_manage_per_apn_timer(int interval_in_secs, int create_timer, int apn_idx) {

	   apn_timer_struct_t *apn_timer_struct = &apn_timers[apn_idx];
	   struct itimerspec timer_spec;

	   if (create_timer) {
	      struct sigaction signal_action;
	      struct sigevent signal_event;
	      signal_action.sa_flags = SA_SIGINFO;
	      signal_action.sa_sigaction = ats_handler;
	      sigemptyset(&signal_action.sa_mask);
	      if (sigaction(SIGRTMIN, &signal_action, NULL) == -1)
		      perror("sigaction");


		  signal_event.sigev_notify = SIGEV_SIGNAL;
		  signal_event.sigev_signo = SIGRTMIN;
		  signal_event.sigev_value.sival_int = apn_idx;  //APN IDX
			  if (timer_create(CLOCK_REALTIME, &signal_event, &apn_timer_struct->timer_id) == -1)
				 perror("timer_create");

		  printf("added timer for APN ID %d for interval %d\n", apn_timer_struct->idx, interval_in_secs);
		}

	   timer_spec.it_value.tv_sec = interval_in_secs; //time threshold from CP for this particular APN
	   timer_spec.it_value.tv_nsec = 0;
	   timer_spec.it_interval.tv_sec = timer_spec.it_value.tv_sec;
	   timer_spec.it_interval.tv_nsec = timer_spec.it_value.tv_nsec;

	   if (timer_settime(apn_timer_struct->timer_id, 0, &timer_spec, NULL) == -1)
			perror("timer_settime");


}


static void ats_handler(int sig, siginfo_t *si, void *uc)
	   {
		   int apn_idx = si->si_value.sival_int;
		   apn_timer_struct_t *apn_timer_struct = &apn_timers[apn_idx];
		   session_t *head = &apn_timer_struct->list_head;
		   struct dp_session_info *session;
		   time_t ts = 0;

		   printf("Timer expired for APN IDX %d on lcore %u\n", apn_timer_struct->idx, rte_lcore_id());

		   if ((!apn_timer_struct->lock) && (head->next != NULL))	{
				  ts = head->next->ts;

				  while (head->next->ts == ts) {
					 head->next->ts = time(NULL);
					 session = get_session_data(head->next->session_id, SESS_MODIFY);
					 if (session == NULL) {
						 printf("Session id 0x%"PRIx64" not found\n", head->next->session_id);
						 continue;
					 }
					 update_vol_on_rec_close(session, CDR_REC_TIME);
					 int ret = rte_ring_enqueue(cdr_ring, (void *)head->next->session_id);
					 if (ret == -ENOBUFS)
						 printf("Failed to Enqueue into cdr_ring after timer threshold\n");
					 ats_list_move_to_tail(apn_idx);
					 ats_manage_per_apn_timer(head->next->ts - ts, UPDATE_TIMER, apn_idx);
				  }

			}
	   }

#if 0
int main(void)
{
	int session_id, apn_id;
	for (apn_id = 0 ; apn_id < MAX_NB_APN ; apn_id++) {
		ats_init(6, apn_id); //Timer threahold 6 seconds

		for (session_id = 0; session_id < MAX_SESSIONS; session_id++ ) {
			ats_list_add_to_tail(session_id, apn_id);
			printf("added session: %d to apn_id %d: \n", session_id, apn_id);
			sleep(rand()%10);
		}
	}

	while(getchar());
return 0;
}
#endif
