# CSER endpoint evidence capability census

## Purpose

This census asks which retirement facts a real endpoint can supply after the
executor that submitted an operation has crashed.  It classifies evidence by
what it proves, rather than by endpoint brand or transport:

- **Outcome evidence** binds a stable effect identity to a result such as
  pending, succeeded, or failed.
- **Quiescence evidence** proves that the endpoint will no longer touch a
  particular resource coordinate.
- **Recoverable evidence** can be queried again after a crash.  A retention or
  deduplication window makes recoverability conditional on that window.

Outcome does not imply quiescence, and an HTTP success response is not a
quiescence proof.  Likewise, a device reset may establish quiescence without
revealing whether an earlier DMA write took effect.

## Census

| Endpoint | Outcome after submitter crash | Quiescence for its governed resource | Recovery boundary |
| --- | --- | --- | --- |
| VirtIO 1.2 device reset plus DMA teardown | Not established by reset | Yes, for the reset device queues and mappings after the profile's drain and IOMMU-revocation sequence | The reset and teardown sequence can be repeated; an earlier DMA outcome may remain unknown |
| Stripe PaymentIntent with an idempotency key | Queryable through the PaymentIntent object; idempotent replay is conditional | No claim about a caller's local DMA resource | Stripe documents idempotency-key retention of at least 24 hours, so replay evidence is not indefinite |
| Amazon EC2 `RunInstances` with a client token | Token-based idempotency plus `DescribeInstances` provides conditional outcome recovery | No; an instance is an independently running resource | EC2 queries are eventually consistent and terminated resources are not retained indefinitely |
| Google Compute long-running Operation | `get`/`wait` exposes operation state and the target can be queried afterward | Operation completion does not prove that the created target is quiescent | Google explicitly requires checking the target after an operation reports `DONE` |
| Kubernetes Job, v1.31 or later | Terminal Job conditions are queryable | Conditional yes for the Job's Pods: terminal conditions are delayed until all Pods terminate | The scope is the Job's Pods, not external cloud or device effects opened by those Pods |
| Amazon SQS FIFO `SendMessage` | Only weak, short-window deduplication evidence | No | Deduplication IDs are remembered for five minutes and do not provide a durable per-message outcome query |
| Stripe outbound webhook | Delivery history does not prove that the receiver durably applied its side effect | No; automatic and manual redelivery may still occur | Stripe retries for up to three days, so timeout or one delivery record is not retirement evidence |
| GitHub `Create an issue` | A returned issue URL is queryable, but a lost POST response leaves no request-keyed recovery query | No | The create API has no caller-supplied durable effect identity that can resolve the accept-before-reply window |

## Primary references

- [VirtIO 1.2 specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
- [Linux DMA API HOWTO](https://docs.kernel.org/core-api/dma-api-howto.html)
- [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)
- [Stripe PaymentIntents API](https://docs.stripe.com/api/payment_intents)
- [Amazon EC2 API idempotency](https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html)
- [EC2 `DescribeInstances`](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
- [Google Compute API requests and responses](https://cloud.google.com/compute/docs/api/how-tos/api-requests-responses)
- [Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/)
- [SQS `SendMessage`](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html)
- [Stripe webhooks](https://docs.stripe.com/webhooks)
- [GitHub Issues REST API](https://docs.github.com/en/rest/issues/issues)

## Consequences for the first adapter

Most cloud/tool endpoints above provide outcome recovery at best.  Device and
controlled-job lifecycles are the common source of quiescence evidence.  The
first reproducible Nexus adapter should therefore use a host-resident durable
tool service with a small controlled transport instead of adding a guest TCP/IP
stack as an unrelated experimental variable.

The service contract is:

1. `submit(effect_id, input_digest)` durably records a job and is idempotent by
   `effect_id`;
2. a fault point may execute the job while dropping its reply;
3. `status(effect_id)` returns `Pending`, `Succeeded(result_digest)`, or
   `Failed(code)` from durable state;
4. terminal outcome remains queryable across guest and service restart.

That component supplies recoverable outcome evidence.  The existing VirtIO DMA
component independently supplies recoverable quiescence evidence for its queue,
page, and generation claims.  Putting both beneath one composite effect tests
component-local retirement without pretending that either fact proves the
other.
