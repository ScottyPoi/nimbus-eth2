import
  std/[options, tables],
  metrics, chronicles,
  ../spec/[crypto, beaconstate, forks, helpers, presets],
  ../spec/datatypes/[phase0, altair],
  ../beacon_clock

logScope: topics = "val_mon"

# Validator monitoring based on the same feature in Lighthouse - using the same
# metrics allows users to more easily reuse monitoring setups

declareGauge validator_monitor_balance_gwei,
  "The validator's balance in gwei.", labels = ["validator"]
declareGauge validator_monitor_effective_balance_gwei,
  "The validator's effective balance in gwei.", labels = ["validator"]
declareGauge validator_monitor_slashed,
  "Set to 1 if the validator is slashed.", labels = ["validator"]
declareGauge validator_monitor_active,
  "Set to 1 if the validator is active.", labels = ["validator"]
declareGauge validator_monitor_exited,
  "Set to 1 if the validator is exited.", labels = ["validator"]
declareGauge validator_monitor_withdrawable,
  "Set to 1 if the validator is withdrawable.", labels = ["validator"]
declareGauge validator_activation_eligibility_epoch,
  "Set to the epoch where the validator will be eligible for activation.", labels = ["validator"]
declareGauge validator_activation_epoch,
  "Set to the epoch where the validator will activate.", labels = ["validator"]
declareGauge validator_exit_epoch,
  "Set to the epoch where the validator will exit.", labels = ["validator"]
declareGauge validator_withdrawable_epoch,
  "Set to the epoch where the validator will be withdrawable.", labels = ["validator"]

declareCounter validator_monitor_prev_epoch_on_chain_attester_hit,
  "Incremented if the validator is flagged as a previous epoch attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_head_attester_hit,
  "Incremented if the validator is flagged as a previous epoch head attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_head_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch head attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_target_attester_hit,
  "Incremented if the validator is flagged as a previous epoch target attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_target_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch target attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_source_attester_hit,
  "Incremented if the validator is flagged as a previous epoch source attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_source_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch source attester during per epoch processing", labels = ["validator"]

declareGauge validator_monitor_prev_epoch_attestations_total,
            "The number of unagg. attestations seen in the previous epoch.",
            labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_attestations_min_delay_seconds,
            "The min delay between when the validator should send the attestation and when it was received.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attestation_aggregate_inclusions,
            "The count of times an attestation was seen inside an aggregate.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attestation_block_inclusions,
            "The count of times an attestation was seen inside a block.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attestation_block_min_inclusion_distance,
            "The minimum inclusion distance observed for the inclusion of an attestation in a block.",
            labels = ["validator"]

declareGauge validator_monitor_prev_epoch_beacon_blocks_total,
            "The number of beacon_blocks seen in the previous epoch.",
            labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_beacon_blocks_min_delay_seconds,
            "The min delay between when the validator should send the block and when it was received.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_aggregates_total,
            "The number of aggregates seen in the previous epoch.",
            labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_aggregates_min_delay_seconds,
            "The min delay between when the validator should send the aggregate and when it was received.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_exits_total,
            "The number of exits seen in the previous epoch.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_proposer_slashings_total,
            "The number of proposer slashings seen in the previous epoch.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attester_slashings_total,
            "The number of attester slashings seen in the previous epoch.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_committee_messages_total,
            "The number of sync committee messages seen in the previous epoch.",
            labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_sync_committee_messages_min_delay_seconds,
            "The min delay between when the validator should send the sync committee message and when it was received.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_contribution_inclusions,
            "The count of times a sync signature was seen inside a sync contribution.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_signature_block_inclusions,
            "The count of times a sync signature was seen inside a block.",
            labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_contributions_total,
            "The number of sync contributions seen in the previous epoch.",
            labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_sync_contribution_min_delay_seconds,
            "The min delay between when the validator should send the sync contribution and when it was received.",
            labels = ["validator"]
declareGauge validator_monitor_validator_in_current_sync_committee,
            "Is the validator in the current sync committee (1 for true and 0 for false)",
            labels = ["validator"]

declareGauge validator_monitor_validators_total,
        "Count of validators that are specifically monitored by this beacon node"
declareCounter validator_monitor_unaggregated_attestation_total,
        "Number of unaggregated attestations seen",
        labels = ["src", "validator"]
declareHistogram validator_monitor_unaggregated_attestation_delay_seconds,
        "The delay between when the validator should send the attestation and when it was received.",
        labels = ["src", "validator"]
declareCounter validator_monitor_sync_committee_messages_total,
        "Number of sync committee messages seen",
        labels = ["src", "validator"]
declareHistogram validator_monitor_sync_committee_messages_delay_seconds,
        "The delay between when the validator should send the sync committee message and when it was received.",
        labels = ["src", "validator"]
declareCounter validator_monitor_sync_contributions_total,
        "Number of sync contributions seen",
        labels = ["src", "validator"]
declareHistogram validator_monitor_sync_contributions_delay_seconds,
        "The delay between when the aggregator should send the sync contribution and when it was received.",
        labels = ["src", "validator"]
declareCounter validator_monitor_aggregated_attestation_total,
        "Number of aggregated attestations seen",
        labels = ["src", "validator"]
declareHistogram validator_monitor_aggregated_attestation_delay_seconds,
        "The delay between then the validator should send the aggregate and when it was received.",
        labels = ["src", "validator"]
declareCounter validator_monitor_attestation_in_aggregate_total,
        "Number of times an attestation has been seen in an aggregate",
        labels = ["src", "validator"]
declareCounter validator_monitor_sync_committee_message_in_contribution_total,
        "Number of times a sync committee message has been seen in a sync contribution",
        labels = ["src", "validator"]
declareHistogram validator_monitor_attestation_in_aggregate_delay_seconds,
        "The delay between when the validator should send the aggregate and when it was received.",
        labels = ["src", "validator"]
declareCounter validator_monitor_attestation_in_block_total,
        "Number of times an attestation has been seen in a block",
        labels = ["src", "validator"]
declareCounter validator_monitor_sync_committee_message_in_block_total,
        "Number of times a validator's sync committee message has been seen in a sync aggregate",
        labels = ["src", "validator"]
declareGauge validator_monitor_attestation_in_block_delay_slots,
        "The excess slots (beyond the minimum delay) between the attestation slot and the block slot.",
        labels = ["src", "validator"]
declareCounter validator_monitor_beacon_block_total,
        "Number of beacon blocks seen",
        labels = ["src", "validator"]
declareHistogram validator_monitor_beacon_block_delay_seconds,
        "The delay between when the validator should send the block and when it was received.",
        labels = ["src", "validator"]
declareCounter validator_monitor_exit_total,
        "Number of beacon exits seen",
        labels = ["src", "validator"]
declareCounter validator_monitor_proposer_slashing_total,
        "Number of proposer slashings seen",
        labels = ["src", "validator"]
declareCounter validator_monitor_attester_slashing_total,
        "Number of attester slashings seen",
        labels = ["src", "validator"]

type
  EpochSummary = object
    # Similar to the state transition, we collect everything that happens in
    # an epoch during that epoch and the one that follows it, then at the end
    # of the monitoring period, we report the statistics to the user.
    # In case of a deep reorg (>1 epoch) this information will be off, but will
    # repair itself in the next epoch, which is a reasonable trade-off between
    # correctness and utility.
    attestations: int64
    attestation_min_delay: Option[Duration]
    attestation_aggregate_inclusions: int64
    attestation_block_inclusions: int64
    attestation_min_block_inclusion_distance: Option[uint64]
    blocks: int64
    block_min_delay: Option[Duration]
    aggregates: int64
    aggregate_min_delay: Option[Duration]

    sync_committee_messages: int64
    sync_committee_message_min_delay: Option[Duration]
    sync_signature_block_inclusions: int64
    sync_signature_contribution_inclusions: int64

    sync_contributions: int64
    sync_contribution_min_delay: Option[Duration]

    exits: int64
    proposer_slashings: int64
    attester_slashings: int64

  MonitoredValidator = object
    id: string # A short id is used above all for metrics
    pubkey: ValidatorPubKey
    index: Option[ValidatorIndex]
    summaries: array[2, EpochSummary] # We monitor the current and previous epochs

  ValidatorMonitor* = object
    epoch: Epoch # The most recent epoch seen in monitoring

    monitors: Table[ValidatorPubKey, ref MonitoredValidator]
    indices: Table[uint64, ref MonitoredValidator]

    knownValidators: int
    autoRegister: bool
    totals: bool

  MsgSource* {.pure.} = enum
    # From where a message is being sent - for compatibility with lighthouse, we
    # don't differentiate sync and requests, but rather use "gossip" - we also
    # don't differentiate in-beacon validators but use "api" as if they were
    # VC:s - this simplifies the initial implementation but should likely be
    # expanded in the future.
    gossip = "gossip"
    api = "api"

proc update_if_lt[T](current: var Option[T], val: T) =
  if current.isNone() or val < current.get():
    current = some(val)

proc register_unaggregated_attestation(self: var EpochSummary, delay: Duration) =
    self.attestations += 1
    update_if_lt(self.attestation_min_delay, delay)

proc register_sync_committee_message(self: var EpochSummary, delay: Duration) =
    self.sync_committee_messages += 1
    update_if_lt(self.sync_committee_message_min_delay, delay)

proc register_aggregated_attestation(self: var EpochSummary, delay: Duration) =
    self.aggregates += 1
    update_if_lt(self.aggregate_min_delay, delay)

proc register_sync_committee_contribution(self: var EpochSummary, delay: Duration) =
    self.sync_contributions += 1
    update_if_lt(self.sync_contribution_min_delay, delay)

proc register_aggregate_attestation_inclusion(self: var EpochSummary) =
    self.attestation_aggregate_inclusions += 1

proc register_sync_signature_contribution_inclusion(self: var EpochSummary) =
    self.sync_signature_contribution_inclusions += 1

proc register_attestation_block_inclusion(self: var EpochSummary, inclusion_lag: uint64) =
    self.attestation_block_inclusions += 1
    update_if_lt(self.attestation_min_block_inclusion_distance, inclusion_lag)

proc register_sync_signature_block_inclusions(self: var EpochSummary) =
    self.sync_signature_block_inclusions += 1

proc register_exit(self: var EpochSummary) =
    self.exits += 1

proc register_proposer_slashing(self: var EpochSummary) =
    self.proposer_slashings += 1

proc register_attester_slashing(self: var EpochSummary) =
    self.attester_slashings += 1

proc addMonitor*(
    self: var ValidatorMonitor, pubkey: ValidatorPubKey,
    index: Option[ValidatorIndex]) =
  if pubkey in self.monitors:
    return

  let id = shortLog(pubkey)

  info "Started monitoring validator", validator = id, pubkey, index

  let monitor = (ref MonitoredValidator)(id: id, index: index)

  self.monitors[pubkey] = monitor

  if index.isSome():
    self.indices[index.get().uint64] = monitor

template metricId: string =
  mixin self, id
  if self.totals: "total" else: id

proc addAutoMonitor*(
    self: var ValidatorMonitor, pubkey: ValidatorPubKey,
    index: ValidatorIndex) =
  if not self.autoRegister:
    return

  # automatic monitors must be registered with index - we don't look for them in
  # the state
  self.addMonitor(pubkey, some(index))

proc init*(T: type ValidatorMonitor, autoRegister = false, totals = false): T =
  T(autoRegister: autoRegister, totals: totals)

template summaryIdx(epoch: Epoch): int = (epoch.uint64 mod 2).int

proc updateEpoch(self: var ValidatorMonitor, epoch: Epoch) =
  # Called at the start of a new epoch to provide a summary of the events 2
  # epochs back then clear the slate for new reporting.
  if epoch <= self.epoch:
    return

  let
    clearMonitor = epoch > self.epoch + 1
    # index of the EpochSummary that we'll first report, then clear
    summaryIdx = epoch.summaryIdx

  if clearMonitor:
    # More than one epoch passed since the last check which makes it difficult
    # to report correctly with the amount of data we store - skip this round
    # and hope things improve
    notice "Resetting validator monitoring", epoch, monitorEpoch = epoch

  self.epoch = epoch

  validator_monitor_validators_total.set(self.monitors.len().int64)

  for (_, monitor) in self.monitors.mpairs():
    if clearMonitor:
      monitor.summaries = default(type(monitor.summaries))
      continue

    let
      id = monitor.id

    let epochSummary = monitor.summaries[summaryIdx]

    validator_monitor_prev_epoch_attestations_total.set(
      epochSummary.attestations, [metricId])

    if epochSummary.attestation_min_delay.isSome():
      validator_monitor_prev_epoch_attestations_min_delay_seconds.observe(
        epochSummary.attestation_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_attestation_aggregate_inclusions.set(
      epochSummary.attestation_aggregate_inclusions, [metricId])
    validator_monitor_prev_epoch_attestation_block_inclusions.set(
      epochSummary.attestation_block_inclusions, [metricId])

    if epochSummary.attestation_min_block_inclusion_distance.isSome():
      validator_monitor_prev_epoch_attestation_block_min_inclusion_distance.set(
        epochSummary.attestation_min_block_inclusion_distance.get().int64, [metricId])

    validator_monitor_prev_epoch_sync_committee_messages_total.set(
      epochSummary.sync_committee_messages, [metricId])

    if epochSummary.sync_committee_message_min_delay.isSome():
      validator_monitor_prev_epoch_sync_committee_messages_min_delay_seconds.observe(
        epochSummary.sync_committee_message_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_sync_contribution_inclusions.set(
      epochSummary.sync_signature_contribution_inclusions, [metricId])
    validator_monitor_prev_epoch_sync_signature_block_inclusions.set(
      epochSummary.sync_signature_block_inclusions, [metricId])

    validator_monitor_prev_epoch_sync_contributions_total.set(
      epochSummary.sync_contributions, [metricId])
    if epochSummary.sync_contribution_min_delay.isSome():
      validator_monitor_prev_epoch_sync_contribution_min_delay_seconds.observe(
        epochSummary.sync_contribution_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_beacon_blocks_total.set(
      epochSummary.blocks, [metricId])

    if epochSummary.block_min_delay.isSome():
      validator_monitor_prev_epoch_beacon_blocks_min_delay_seconds.observe(
        epochSummary.block_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_aggregates_total.set(
        epochSummary.aggregates, [metricId])

    if epochSummary.aggregate_min_delay.isSome():
      validator_monitor_prev_epoch_aggregates_min_delay_seconds.observe(
        epochSummary.aggregate_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_exits_total.set(
      epochSummary.exits, [metricId])

    validator_monitor_prev_epoch_proposer_slashings_total.set(
        epochSummary.proposer_slashings, [metricId])

    validator_monitor_prev_epoch_attester_slashings_total.set(
      epochSummary.attester_slashings, [metricId])

    monitor.summaries[summaryIdx] = default(type(monitor.summaries[summaryIdx]))

proc is_active_unslashed_in_previous_epoch(status: RewardStatus): bool =
  let flags = status.flags
  RewardFlags.isActiveInPreviousEpoch in flags and
    RewardFlags.isSlashed notin flags

proc is_previous_epoch_source_attester(status: RewardStatus): bool =
  status.is_previous_epoch_attester.isSome()

proc is_previous_epoch_head_attester(status: RewardStatus): bool =
  RewardFlags.isPreviousEpochHeadAttester in status.flags

proc is_previous_epoch_target_attester(status: RewardStatus): bool =
  RewardFlags.isPreviousEpochTargetAttester in status.flags

proc registerEpochInfo*(
    self: var ValidatorMonitor, epoch: Epoch, info: ForkedEpochInfo) =
  # Register rewards, as computed during the epoch transition that lands in
  # `epoch` - the rewards will be from attestations that were created at
  # `epoch - 2`.

  if epoch < 2 or self.monitors.len == 0:
    return

  withEpochInfo(info):
    when info is phase0.EpochInfo:
      debug "Registering rewards with monitor",
        monitors = self.monitors.len(),
        rewards = info.statuses.len()

      for _, monitor in self.monitors:
        # We subtract two from the state of the epoch that generated these summaries.
        #
        # - One to account for it being the previous epoch.
        # - One to account for the state advancing an epoch whilst generating the validator
        #   statuses.
        if monitor.index.isNone:
          continue

        let idx = monitor.index.get()

        if info.statuses.lenu64 <= idx.uint64:
          # No summary for this validator (yet?)
          debug "No reward information for validator",
            id = monitor.id, idx
          continue

        let
          prev_epoch = epoch - 2
          id = monitor.id

          # /*
          #   * These metrics are reflected differently between Base and Altair.
          #   *
          #   * For Base, any attestation that is included on-chain will match the source.
          #   *
          #   * However, in Altair, only attestations that are "timely" are registered as
          #   * matching the source.
          #   */

        let status = info.statuses[idx]

        if not status.is_active_unslashed_in_previous_epoch():
          # Monitored validator is not active, due to awaiting activation
          # or being exited/withdrawn. Do not attempt to report on its
          # attestations.
          continue

        let previous_epoch_matched_source = status.is_previous_epoch_source_attester()
        let previous_epoch_matched_target = status.is_previous_epoch_target_attester()
        let previous_epoch_matched_head = status.is_previous_epoch_head_attester()
        let previous_epoch_matched_any =
          previous_epoch_matched_source or
          previous_epoch_matched_target or
          previous_epoch_matched_head

        # Indicates if any attestation made it on-chain.
        # For Base states, this will be *any* attestation whatsoever. For Altair states,
        # this will be any attestation that matched a "timely" flag.
        if previous_epoch_matched_any:
          validator_monitor_prev_epoch_on_chain_attester_hit.inc(1, [metricId])

          info "Previous epoch attestation success",
            matched_source = previous_epoch_matched_source,
            matched_target = previous_epoch_matched_target,
            matched_head = previous_epoch_matched_head,
            epoch = prev_epoch,
            validator = id
        else:
          validator_monitor_prev_epoch_on_chain_attester_miss.inc(1, [metricId])

          warn "Previous epoch attestation missing",
            epoch = prev_epoch,
            validator = id

        # Indicates if any on-chain attestation hit the head.
        if previous_epoch_matched_head:
          validator_monitor_prev_epoch_on_chain_head_attester_hit.inc(1, [metricId])
        else:
          validator_monitor_prev_epoch_on_chain_head_attester_miss.inc(1, [metricId])
          notice "Attestation failed to match head",
            epoch = prev_epoch,
            validator = id

        # Indicates if any on-chain attestation hit the target.
        if previous_epoch_matched_target:
          validator_monitor_prev_epoch_on_chain_target_attester_hit.inc(1, [metricId])
        else:
          validator_monitor_prev_epoch_on_chain_target_attester_miss.inc(1, [metricId])

          notice "Attestation failed to match target",
            epoch = prev_epoch,
            validator = id

        # // Indicates the number of sync committee signatures that made it into
        # // a sync aggregate in the current_epoch (state.epoch - 1).
        # // Note: Unlike attestations, sync committee signatures must be included in the
        # // immediate next slot. Hence, num included sync aggregates for `state.epoch - 1`
        # // is available right after state transition to state.epoch.
        let current_epoch = epoch - 1
        # TODO altair sync committee monitoring
        # if epochSummary.sync_committee.isSome():
        #   if sync_committee.contains(pubkey):
        #     validator_monitor_validator_in_current_sync_committee.set(1, [metricId])

        #     # let epoch_summary = monitored_validator.summaries.read();
        #     # if let Some(summary) = epoch_epochSummary.get(&current_epoch) {
        #     #     info!(
        #     #         self.log,
        #     #         "Current epoch sync signatures";
        #     #         "included" => epochSummary.sync_signature_block_inclusions,
        #     #         "expected" => T::slots_per_epoch(),
        #     #         "epoch" => current_epoch,
        #     #         "validator" => id,
        #     #     );
        #     # }
        #   else:
        #     validator_monitor_validator_in_current_sync_committee.set(0, [metricId])
        #     # debug!(
        #     #     self.log,
        #     #     "Validator isn't part of the current sync committee";
        #     #     "epoch" => current_epoch,
        #     #     "validator" => id,
        #     # );
    else:
      # TODO altair
      discard
  self.updateEpoch(epoch)

proc registerState*(self: var ValidatorMonitor, state: auto) =
  # Update indices for the validators we're monitoring
  for v in self.knownValidators..<state.validators.len:
    self.monitors.withValue(state.validators[v].pubkey, monitor):
      monitor[].index = some(ValidatorIndex(v))
      self.indices[uint64(v)] = monitor[]

  self.knownValidators = state.validators.len

  let
    current_epoch = state.slot.epoch

  # Update metrics for monitored validators according to the latest rewards
  for (_, monitor) in self.monitors.mpairs():
    if not monitor[].index.isSome():
      continue

    let idx = monitor[].index.get()
    if state.balances.lenu64 <= idx.uint64:
      continue

    let id = monitor[].id
    validator_monitor_balance_gwei.set(state.balances[idx].toGaugeValue(), [metricId])
    validator_monitor_effective_balance_gwei.set(
      state.validators[idx].effective_balance.toGaugeValue(), [metricId])
    validator_monitor_slashed.set(
      if state.validators[idx].slashed: 1 else: 0, [metricId])
    validator_monitor_active.set(
      if is_active_validator(state.validators[idx], current_epoch): 1 else: 0, [metricId])
    validator_monitor_exited.set(
      if is_exited_validator(state.validators[idx], current_epoch): 1 else: 0, [metricId])
    validator_monitor_withdrawable.set(
      if is_withdrawable_validator(state.validators[idx], current_epoch): 1 else: 0, [metricId])
    validator_activation_eligibility_epoch.set(
      state.validators[idx].activation_eligibility_epoch.toGaugeValue(), [metricId])
    validator_activation_epoch.set(
      state.validators[idx].activation_epoch.toGaugeValue(), [metricId])
    validator_exit_epoch.set(
      state.validators[idx].exit_epoch.toGaugeValue(), [metricId])
    validator_withdrawable_epoch.set(
      state.validators[idx].withdrawable_epoch.toGaugeValue(), [metricId])

template withEpochSummary(self: var ValidatorMonitor, monitor: var MonitoredValidator, epoch: Epoch, body: untyped) =
  mixin summaryIdx
  if epoch == self.epoch or epoch + 1 == self.epoch:
    template epochSummary: untyped {.inject.} = monitor.summaries[summaryIdx(epoch)]
    body

template withMonitor(self: var ValidatorMonitor, key: ValidatorPubKey, body: untyped): untyped =
  self.monitors.withValue(key, valuex):
    template monitor: untyped {.inject.} = valuex[][]
    body

template withMonitor(self: var ValidatorMonitor, idx: uint64, body: untyped): untyped =
  self.indices.withValue(idx, valuex):
    template monitor: untyped {.inject.} = valuex[][]
    body

template withMonitor(self: var ValidatorMonitor, idx: ValidatorIndex, body: untyped): untyped =
  withMonitor(self, idx.uint64, body)

proc delay(slot: Slot, time: BeaconTime, offset: Duration): Duration =
  time + offset - slot.toBeaconTime()

proc registerUnaggregatedAttestation*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    attestation: Attestation,
    idx: ValidatorIndex) =
  let data = attestation.data
  let epoch = data.slot.epoch
  # TODO offset
  let delay = delay(data.slot, seen_timestamp, seconds(0))

  self.withMonitor(idx):
    let id = monitor.id
    validator_monitor_unaggregated_attestation_total.inc(1, [$src, metricId])
    validator_monitor_unaggregated_attestation_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Unaggregated attestation", attestation, idx

    self.withEpochSummary(monitor, epoch):
      epochSummary.register_unaggregated_attestation(delay)

proc registerAggregatedAttestation*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    signed_aggregate_and_proof: SignedAggregateAndProof,
    attesting_indices: openArray[ValidatorIndex]) =
  let data = signed_aggregate_and_proof.message.aggregate.data
  let epoch = data.slot.epoch
  # TODO offset
  let delay = delay(data.slot, seen_timestamp, seconds(0))

  let aggregator_index = signed_aggregate_and_proof.message.aggregator_index
  self.withMonitor(aggregator_index):
    let id = monitor.id
    validator_monitor_aggregated_attestation_total.inc(1, [$src, metricId])
    validator_monitor_aggregated_attestation_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Aggregated attestation",
      attestation = data, src, validator = id

    self.withEpochSummary(monitor, epoch):
      epochSummary.register_aggregated_attestation(delay)

  for idx in attesting_indices:
    self.withMonitor(idx):
      let id = monitor.id
      validator_monitor_attestation_in_aggregate_total.inc(1, [$src, metricId])
      validator_monitor_attestation_in_aggregate_delay_seconds.observe(
        delay.toFloatSeconds(), [$src, metricId])

      info "Attestation included in aggregate",
        attestation = data, src, validator = id

      self.withEpochSummary(monitor, epoch):
          epochSummary.register_aggregate_attestation_inclusion()

proc registerAttestationInBlock*(
    self: var ValidatorMonitor,
    data: AttestationData,
    attesting_index: ValidatorIndex,
    blck: auto) =
  let inclusion_lag = (blck.slot - data.slot) - MIN_ATTESTATION_INCLUSION_DELAY
  let epoch = data.slot.epoch

  self.withMonitor(attesting_index):
    let id = monitor.id
    validator_monitor_attestation_in_block_total.inc(1, ["block", id])
    validator_monitor_attestation_in_block_delay_slots.set(inclusion_lag.int64, ["block", id])

    info "Attestation included in block",
      attestation = data,
      inclusion_lag_slots = inclusion_lag,
      validator = id

    self.withEpochSummary(monitor, epoch):
      epochSummary.register_attestation_block_inclusion(inclusion_lag)

proc registerBeaconBlock*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    blck: auto) =
  self.withMonitor(blck.proposer_index):
    let id = monitor.id
    let delay = delay(blck.slot, seen_timestamp, seconds(0))

    validator_monitor_beacon_block_total.inc(1, [$src, metricId])
    validator_monitor_beacon_block_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Block from API",
      blck = shortLog(blck),
      src = src,
      validator = id

proc registerSyncCommitteeMessage*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    sync_committee_message: SyncCommitteeMessage) =
  self.withMonitor(sync_committee_message.validator_index):
    let id = monitor.id

    let epoch = sync_committee_message.slot.epoch
    # TODO offset
    let delay = delay(sync_committee_message.slot, seen_timestamp, seconds(0))

    validator_monitor_sync_committee_messages_total.inc(1, [$src, metricId])
    validator_monitor_sync_committee_messages_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Sync committee message",
        msg = shortLog(sync_committee_message.beacon_block_root),
        src, validator = id

    self.withEpochSummary(monitor, epoch):
      epochSummary.register_sync_committee_message(delay)

proc registerSyncCommitteeContribution*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    sync_contribution: SignedContributionAndProof,
    participant_pubkeys: openArray[ValidatorPubKey]) =
  let slot = sync_contribution.message.contribution.slot
  let epoch = slot.epoch
  let beacon_block_root = sync_contribution.message.contribution.beacon_block_root
  # TODO offset
  let delay = delay(slot, seen_timestamp, seconds(0))

  let aggregator_index = sync_contribution.message.aggregator_index
  self.withMonitor(aggregator_index):
    let id = monitor.id

    validator_monitor_sync_contributions_total.inc(1, [$src, metricId])
    validator_monitor_sync_contributions_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Sync contribution",
      msg = shortLog(sync_contribution),
      src, validator = id

    self.withEpochSummary(monitor, epoch):
      epochSummary.register_sync_committee_contribution(delay)

  for validator_pubkey in participant_pubkeys:
    self.withMonitor(validator_pubkey):
      let id = monitor.id

      validator_monitor_sync_committee_message_in_contribution_total.inc(1, [$src, metricId])

      info "Sync signature included in contribution",
          msg = shortLog(sync_contribution),
          src,
          validator = id

      self.withEpochSummary(monitor, epoch):
        epochSummary.register_sync_signature_contribution_inclusion()

proc registerSyncAggregateInBlock*(
    self: var ValidatorMonitor,
    slot: Slot,
    beacon_block_root: Eth2Digest,
    participant_pubkeys: openArray[ValidatorPubKey]) =
  let epoch = slot.epoch

  for validator_pubkey in participant_pubkeys:
    self.withMonitor(validator_pubkey):
      let id = monitor.id

      validator_monitor_sync_committee_message_in_block_total.inc(1, ["block", id])

      info "Sync signature included in block",
          head = beacon_block_root,
          epoch = epoch,
          slot = slot,
          validator = id

      self.withEpochSummary(monitor, epoch):
        epochSummary.register_sync_signature_block_inclusions()

proc registerVoluntaryExit*(
  self: var ValidatorMonitor, src: MsgSource, exit: VoluntaryExit) =
  self.withMonitor(exit.validator_index.ValidatorIndex):
    let id = monitor.id
    let epoch = exit.epoch

    validator_monitor_exit_total.inc(1, [$src, metricId])

    info "Voluntary exit",
      epoch = epoch, validator = id, src = src

    self.withEpochSummary(monitor, epoch): epochSummary.register_exit()

proc registerProposerSlashing*(
  self: var ValidatorMonitor, src: MsgSource, slashing: ProposerSlashing) =
  let proposer = slashing.signed_header_1.message.proposer_index

  self.withMonitor(proposer):
    let slot = slashing.signed_header_1.message.slot
    let epoch = slot.epoch
    let root_1 = hash_tree_root(slashing.signed_header_1.message)
    let root_2 = hash_tree_root(slashing.signed_header_2.message)
    let id = monitor.id

    validator_monitor_proposer_slashing_total.inc(1, [$src, metricId])

    warn "Proposer slashing",
      root_2 = root_2,
      root_1 = root_1,
      slot = slot,
      validator = id,
      src = src

    self.withEpochSummary(monitor, epoch): epochSummary.register_proposer_slashing()

proc registerAttesterSlashing*(
    self: var ValidatorMonitor, src: MsgSource, slashing: AttesterSlashing) =
  let data = slashing.attestation_1.data

  for idx in slashing.attestation_2.attesting_indices:
    if idx notin slashing.attestation_1.attesting_indices.asSeq:
      continue

    self.withMonitor(idx):
      let id = monitor.id
      let epoch = data.slot.epoch

      validator_monitor_attester_slashing_total.inc(1, [$src, metricId])

      warn "Attester slashing",
          epoch = epoch,
          slot = data.slot,
          validator = id,
          src = src

      self.withEpochSummary(monitor, epoch):
        epochSummary.register_attester_slashing()
