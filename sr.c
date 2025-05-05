#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "gbn.h"

#define RTT  16.0       /* round trip time. MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6    /* the maximum number of buffered unacked packet */
#define SEQSPACE 7      /* the min sequence space for GBN must be at least windowsize + 1 */
#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

/* generic procedure to compute the checksum of a packet. Used by both sender and receiver */
int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for (i = 0; i < 20; i++) {
    checksum += (int)(packet.payload[i]);
  }

  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet)) {
    return false;
  } else {
    return true;
  }
}

/********* Sender (A) variables and functions ************/

static struct pkt buffer[WINDOWSIZE];  /* array for storing packets waiting for ACK */
static int windowfirst, windowlast;    /* array indexes of the first/last packet awaiting ACK */
static int windowcount;                /* the number of packets currently awaiting an ACK */
static int A_nextseqnum;               /* the next sequence number to be used by the sender */ 

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;

  /* if not blocked waiting on ACK */
  if (windowcount < WINDOWSIZE) {
    if (TRACE > 1) {
      printf("----A: New message arrives, send window is not full, send new message to layer3!\n");
    }

    /* create packet */
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) {
      sendpkt.payload[i] = message.data[i];
    }
    sendpkt.checksum = ComputeChecksum(sendpkt);

    /* put packet in window buffer */
    windowlast = (windowlast + 1) % WINDOWSIZE;
    buffer[windowlast] = sendpkt;
    windowcount++;

    /* send out packet */
    if (TRACE > 0) {
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    }
    tolayer3(A, sendpkt);

    /* start timer if first packet in window */
    if (windowcount == 1) {
      starttimer(A, RTT);
    }

    /* get next sequence number, wrap back to 0 */
    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  /* if blocked, window is full */
  else {
    if (TRACE > 0) {
      printf("----A: New message arrives, send window is full\n");
    }
    window_full++;
  }
}

/* called from layer 3, when a packet arrives for layer 4 */
static bool acked[WINDOWSIZE];  /* track ACKs for each packet in the window */
void process_ack(struct pkt packet, int *ackcount)
{
  int seqfirst = buffer[windowfirst].seqnum;
  int seqlast = buffer[windowlast].seqnum;

  /* Check if the received ACK is within the window range */
  if (((seqfirst <= seqlast) && (packet.acknum >= seqfirst && packet.acknum <= seqlast)) ||
      ((seqfirst > seqlast) && (packet.acknum >= seqfirst || packet.acknum <= seqlast))) {

      if (TRACE > 0) {
          printf("----A: ACK %d is not a duplicate\n", packet.acknum);
      }

      new_ACKs++;

      /* Calculate how many packets are acknowledged */
      if (packet.acknum >= seqfirst) {
          *ackcount = packet.acknum + 1 - seqfirst;
      } else {
          *ackcount = SEQSPACE - seqfirst + packet.acknum;
      }
  }
}

void update_window_and_timer(int ackcount)
{
  int i;  
  
  /* Slide window by the number of packets acknowledged */
  windowfirst = (windowfirst + ackcount) % WINDOWSIZE;

  /* Remove acknowledged packets from the window buffer */
  for (i = 0; i < ackcount; i++) {
    windowcount--;
  }

  /* Stop timer and restart if there are more unacknowledged packets */
  stoptimer(A);
  if (windowcount > 0) {
      starttimer(A, RTT);
  }
}

void slide_window_forward()
{
  /* Slide window over any consecutive acknowledged slots */
  while (windowcount > 0 && acked[windowfirst]) {
      acked[windowfirst] = false;  /* Clear for reuse */
      windowfirst = (windowfirst + 1) % WINDOWSIZE;
      windowcount--; 
      stoptimer(A);   /* Stop the timer for the current window */

      if (windowcount > 0) {
          starttimer(A, RTT);  /* Restart timer if necessary */
      }
  }
}

void A_input(struct pkt packet)
{
  int ackcount = 0;

  /* Process only if the ACK is not corrupted */
  if (!IsCorrupted(packet)) {
      if (TRACE > 0) {
          printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
      }
      total_ACKs_received++;

      /* Check if individual packets have been ACKed */
      if (windowcount != 0) {
          process_ack(packet, &ackcount);

          if (ackcount > 0) {
              /* Update window and manage the timer */
              update_window_and_timer(ackcount);
              
              /* Slide window forward over acknowledged slots */
              slide_window_forward();
          }
      } else {
          if (TRACE > 0) {
              printf("----A: duplicate ACK received, do nothing!\n");
          }
      }
  } else {
      if (TRACE > 0) {
          printf("----A: corrupted ACK is received, do nothing!\n");
      }
  }
}

/* called when A's timer goes off */
void A_timerinterrupt(void)
{
  if (TRACE > 0) {
      /* Print timeout message */
      printf("----A: time out, resend packets!\n");
  }

  /* Log the packet sequence number before resending */
  int seqnum_to_resend = buffer[windowfirst].seqnum;  
  if (TRACE > 0) {
      printf("---A: resending packet %d\n", seqnum_to_resend);
  }

  /* Increment resent packet count */
  packets_resent++;

  /* Resend the packet */
  tolayer3(A, buffer[windowfirst]);

  /* Restart the timer for the next packet */
  starttimer(A, RTT);
}

/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init(void)
{
  int i;
  /* initialise A's window, buffer and sequence number */
  A_nextseqnum = 0;  /* A starts with seq num 0, do not change this */
  windowfirst = 0;
  windowlast = -1;   /* windowlast is where the last packet sent is stored.
                     new packets are placed in winlast + 1
                     so initially this is set to -1 */
  windowcount = 0;
  for (i = 0; i < WINDOWSIZE; i++) {
    acked[i] = false;
  }
}

/********* Receiver (B) variables and procedures ************/

static int expectedseqnum; /* the sequence number expected next by the receiver */
static int B_nextseqnum;   /* the sequence number for the next packets sent by B */
static struct pkt recvbuf[WINDOWSIZE];
static bool recvd[WINDOWSIZE]; 

void B_input(struct pkt packet)
{
    struct pkt sendpkt;
    int i, idx;

    /* Check if packet is not corrupted */
    if (!IsCorrupted(packet)) {
        /* Calculate the difference in sequence number with wrap-around */
        int diff = (packet.seqnum - expectedseqnum + SEQSPACE) % SEQSPACE;
        
        if (diff < WINDOWSIZE) {  /* If the packet is within the window */
            if (TRACE > 0) {
                printf("----B: packet %d is correctly received, send ACK!\n", packet.seqnum);
            }
            packets_received++;

            /* If packet is not yet received, buffer it */
            idx = packet.seqnum % WINDOWSIZE;
            if (!recvd[idx]) {
                recvbuf[idx] = packet;
                recvd[idx] = true;
            }

            /* Acknowledge the received packet */
            sendpkt.acknum = packet.seqnum;

            /* Deliver in-sequence packets starting at expectedseqnum */
            idx = expectedseqnum % WINDOWSIZE;
            while (recvd[idx]) {
                tolayer5(B, recvbuf[idx].payload);  /* Deliver the packet to layer 5 */
                recvd[idx] = false;  /* Mark the packet as delivered */

                /* Update expected sequence number */
                expectedseqnum = (expectedseqnum + 1) % SEQSPACE;

                /* Move to the next sequence number in the window */
                idx = expectedseqnum % WINDOWSIZE;
            }
        } else {
            /* The packet is a duplicate, check if it's within the already-delivered window */
            int back = (expectedseqnum - packet.seqnum + SEQSPACE) % SEQSPACE;
            if (back > 0 && back <= WINDOWSIZE) {
                if (TRACE > 0) {
                    printf("----B: packet %d is correctly received, send ACK!\n", packet.seqnum);
                }
                packets_received++;
                sendpkt.acknum = packet.seqnum;
            }
        }
    } else {
        /* If packet is corrupted or out of order, resend the last ACK */
        if (TRACE > 0) {
            printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
        }

        /* Send the ACK for the last valid packet */
        sendpkt.acknum = (expectedseqnum == 0) ? SEQSPACE - 1 : expectedseqnum - 1;
    }

    /* Build and send the ACK */
    sendpkt.seqnum = B_nextseqnum;
    B_nextseqnum = (B_nextseqnum + 1) % 2;  /* Alternate the sequence number for ACKs */
    
    /* Fill the payload with 0's (no data to send) */
    for (i = 0; i < 20; i++) {
        sendpkt.payload[i] = '0';
    }
    
    /* Compute the checksum */
    sendpkt.checksum = ComputeChecksum(sendpkt);
    
    /* Send the ACK packet */
    tolayer3(B, sendpkt);
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void)
{
  expectedseqnum = 0;
  B_nextseqnum = 1;
  int i;
  for(i = 0; i < WINDOWSIZE; i++) {
    recvd[i] = false;
  }
}

void B_output(struct msg message)
{
}

void B_timerinterrupt(void)
{
}
