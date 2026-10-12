#ifndef QLINQ_TRANSPORT_RECOVERY_H
#define QLINQ_TRANSPORT_RECOVERY_H

#include "transport.h"
#include "transport_recovery_state.h"
#include "transport_wire.h"

/* Callers resolve the receive subscription before applying these transitions.
 */
bool transport_recovery_was_delivered(const transport_object_gap_state_t *state,
                                      uint64_t object_id);
void transport_recovery_observe(transport_object_gap_state_t *state,
                                uint64_t group_id, uint64_t object_id);
void transport_recovery_delivered(transport_conn_t *conn, uint8_t alias,
                                  uint64_t group_id, uint64_t object_id);
/* NULL means success; failures retain their protocol close reason. */
const char *
transport_recovery_checkpoint(transport_conn_t *conn,
                              const qlinq_wire_track_checkpoint_t *checkpoint);
const char *transport_recovery_finish(transport_conn_t *conn,
                                      const qlinq_wire_track_end_t *end);
void transport_recovery_flush_acks(transport_conn_t *conn);
bool transport_recovery_send_nack(transport_conn_t *conn, uint8_t alias,
                                  uint64_t group_id, uint64_t object_id,
                                  const uint16_t *missing, uint16_t count,
                                  bool whole_object);
void transport_recovery_tick(transport_t *t, int64_t now_ms);
int64_t transport_recovery_deadline(const transport_conn_t *conn);

#endif
