# Merchant Dashboard: Self-Serve Customer Refunds

We're getting too many Zendesk tickets asking support to refund accidental or disputed orders.

Add a "Refund Payment" button on the Charge Details page (`POST /v1/charges/{charge_id}/refund`) in the Merchant Dashboard so merchants and support agents can issue full or partial refunds via Stripe, update the order status to `REFUNDED`, and send the customer a confirmation email. Make sure we don't refund more than the original charge.
