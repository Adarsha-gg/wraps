# Submission packet: XRP Ledger Hackathon, Mastercard Agentic Track

Form: Microsoft Forms, one entry per team. Fields below are in form order.

## Audit (fix blockers first)

| # | Item | Status | Fix |
|---|---|---|---|
| 6 | Demo video URL | NEEDS-USER | Record, upload as public or unlisted (YouTube or Loom), test the link in a private window. |
| 4 | Live AP4M receipt | NEEDS-USER | Add an explorer link to one real `VoucherRedeemed` tx if you have one. It is the strongest proof for this track. |
| 1 | Team name matches registration | NEEDS-USER | Code uses `CBC`. You typed `cbc`. Use the exact registered spelling. |
| 8 | Five confirmations | NEEDS-USER | The team ticks these. Check rights to the Figma screens and the architecture image. |
| 5 | Repo is public, link works | READY | `hrishabhayush/wraps` is public. |
| 7 | Pitch deck URL | READY (optional) | Points at `docs/PITCH-DECK.md`. Swap for a slides link if you have one. |
| 3, 4 | Under 3000 characters | READY | Counts are under each heading. |

---

## 1. Team Name

CBC

## 2. Project Name

Wraps

## 3. Project Description

1869 / 3000 characters.

```text
Wraps is incognito mode for AI agents.

AI agents now pay for data on their own with x402 on XRPL. The catch is that every payment is public forever: the wallet, the merchant, the amount and the exact time. We built a bot that reads these payments from XRPL mainnet. In one sample, 50 payments to a single merchant came from 50 different wallets, and 44 of them were funded straight from exchanges, so the exchange knows who is behind each one. If a fund's research agent buys data this way, anyone can watch what it is researching.

Wraps lets agents pay without being watched. The agent tops up with RLUSD and gets blind tokens back. The issuer signs these tokens without seeing them, so it can never link a payment back to the agent that made it. The agent's traffic also goes through the Wraps VPN, so merchants and websites see our relay, not the agent. Relays run in the US, the Netherlands and the UK.

You don't have to trust us. The issuer and relays run in Google Cloud Confidential Space, sealed hardware that proves which code is running. Before the agent pays anything, it checks that proof. If someone changes the code, the agent refuses to pay.

The agent spends money on its own, so we made that safe too. It decides what to buy based on its task and its budget, and the spending limits live in code, not in the AI model. In our demo, the agent buys data with a hidden "buy 500 more" instruction in it and ignores it.

You can try Wraps three ways: a Mac menu bar app that tops up with RLUSD and connects to the VPN in one click, a browser agent that pays for data through Mastercard AP4M, and a demo you can run from the repo.

We also tested Wraps against the 8 security rules from a 2026 study of x402 payment services, which found that every one of the 15 services it tested broke at least one rule. Wraps passes all 45 of our tests for those rules.
```

## 4. How does your solution use Mastercard AP4M / Agentic Payments?

1483 / 3000 characters.

```text
Wraps uses Mastercard AP4M to pay for things. AP4M moves the money. Wraps makes sure nobody can watch the agent while it pays.

Our agent has its own AP4M payment channel on XRPL EVM testnet, funded with RLUSD. When it hits a paid API, the API answers with an x402 payment request. The agent checks the price against its budget, signs an AP4M voucher itself, and gets the data back once the merchant redeems the voucher on the AP4M ledger. In our demo, the agent buys three data reports this way and shows a receipt for each one.

The agent decides for itself when to pay. You give it a task and a budget, and it browses, reads and reasons about what it needs. It only buys a report when that report helps answer the task, and it weighs the price against what is left in its budget. A budget is a limit, not a charge: if free sources are enough, the agent spends nothing. It explains each decision as it goes, so you can see why it paid.

Wraps wraps every AP4M payment in privacy. The agent only pays when its traffic goes through a Wraps relay, a VPN server running in Google Confidential Space. The agent verifies that relay before it connects, so the merchant sees the relay, not the agent.

Wraps also keeps the agent's spending safe. Budgets are set in code, not by the AI model. The model cannot change who gets paid or raise its own budget, and a payment that gets interrupted resumes instead of paying twice.

AP4M lets agents pay. Wraps lets them pay without being watched.
```

## 5. Public Source Code Repository URL

https://github.com/hrishabhayush/wraps

## 6. Demo Video URL

NEEDS-USER: paste the public video link.

## 7. Pitch Deck URL

https://github.com/hrishabhayush/wraps/blob/main/docs/PITCH-DECK.md

## 8. Confirmations

The team ticks all five only if each is true. Not submitted yet.
