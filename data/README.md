# Gray Swan Arena challenge and public walkthrough archive

Research snapshot: **2026-07-29**  
Re-verified and extended: **2026-09-03**  
Primary catalog: [Gray Swan Arena](https://app.grayswan.ai/arena)

This is a best-effort compilation of every challenge exposed by the public Arena catalog and every publicly accessible **writeup** or walkthrough I could verify. I interpreted “wiretap” in the request as “writeup.” The compilation links to potentially dual-use material but does not reproduce jailbreak payloads or harmful procedural content.

## At a glance

- The live catalog exposes **27 named challenge cards**: **24 completed** (including one closed) and **3 ongoing/practice**.
- The ongoing/practice cards are The Labyrinth (Training Quest #1) — rebranded from “Getting Started Quest #1” — Proving Ground, and Hazard Hunt: Chem, Bio, Cyber, Misc.
- Two new competitive challenges launched and finished between snapshots: **Indirect Prompt Injection August ’26** ($30,000, the largest IPI pool to date) and **IPI Lucky Break** ($5,000 raffle built on revamped Proving Ground challenges).
- Indirect Prompt Injection July ’26 has ended (Wave 1 ran Jul 27 – Aug 03; all $20,000 awarded).
- Proving Ground has reached **Wave 26**. The 2026-07-29 “Show All Waves” view exposed **21 waves**: 2, 3, 5, 6, 9, and 11–26; the 2026-09-03 sync re-verified the Wave 21–26 slugs against the live homepage showcase.
- Historical snapshots recover **Wave 1**, while an official Gray Swan article recovers **Wave 4**.
- Waves **7, 8, and 10** were not present in the live UI, indexed search results, or available Internet Archive captures. They are recorded as gaps rather than reconstructed from guesses.
- I verified **26 public resources** with meaningful challenge-specific or Arena-specific content: official recaps, papers/code, participant writeups, videos, and adjacent analyses. The catalog holds 35 entries; the remaining nine are lower-specificity contextual resources retained for completeness. Many challenges have no independently published walkthrough that could be located.

Machine-readable versions:

- [arena_challenges.csv](arena_challenges.csv)
- [proving_ground_waves.csv](proving_ground_waves.csv)
- [public_writeups_walkthroughs.csv](public_writeups_walkthroughs.csv)

Active-challenge field kit:

- [Hazard Hunt Q3 playbook](HAZARD_HUNT_PLAYBOOK.md)
- [Hazard Hunt Q3 run log template](hazard_hunt_q3_run_log.csv)
- [Indirect Prompt Injection July ’26 playbook](ACTIVE_CHALLENGE_PLAYBOOK.md) (historical)
- [Manual testing run log](ipi_july_2026_run_log.csv) (historical)

## Named challenge inventory

“Coverage” means a substantive public recap, writeup, walkthrough, or technical report—not merely the challenge page or a promotional announcement.

| # | Challenge | Public status on 2026-09-03 | Prize shown | Verified public coverage |
|---:|---|---|---:|---|
| 1 | [Indirect Prompt Injection July ’26](https://app.grayswan.ai/arena/challenge/ipi-july-2026) | Completed | $20,000 | None located; ended 2026-08-03 with all $20,000 awarded |
| 2 | [The Labyrinth (Training Quest #1)](https://app.grayswan.ai/arena/challenge/onboarding-quest-1) | Ongoing/practice | Free | Formerly “Getting Started Quest #1”, rebranded on the live catalog; [Beginner video walkthrough](https://www.youtube.com/watch?v=S0IKgLtmxs4) covers Arena onboarding generally |
| 3 | [The Labyrinth: Challenge Version](https://app.grayswan.ai/arena/challenge/labyrinth-challenge-version) | Completed | Free | [Participant “most memorable break”](https://www.thaiaiaudit.com/en/my-most-memorable-break-in-gray-swan-2/) appears to describe its prisoner/guard scenario; mapping is probable, not explicitly named |
| 4 | [Indirect Prompt Injection June ’26](https://app.grayswan.ai/arena/challenge/ipi-june-2026) | Completed | $22,000 | None located |
| 5 | [Cyber Bypass](https://app.grayswan.ai/arena/challenge/cyber-bypass) | Completed | $50,000 | [Participant result/mini-writeup](https://www.linkedin.com/posts/uhyang03_anthropic%EC%9D%B4-%ED%9B%84%EC%9B%90%ED%95%98%EA%B3%A0-gray-swan-arena%EC%97%90%EC%84%9C-%EA%B0%9C%EC%B5%9C%EB%90%9C-cyber-activity-7476074403743604736-5xRf) |
| 6 | [Indirect Prompt Injection Q2 2026](https://app.grayswan.ai/arena/challenge/ipi-q2-2026) | Completed | $20,000 | [Participant research synthesis](https://manifund.org/projects/when-language-becomes-workflow); not a step-by-step walkthrough |
| 7 | [Human / Browser Agent Robustness](https://app.grayswan.ai/arena/challenge/human-browser-agent-robustness) | Completed | $100,004 | [Participant research synthesis](https://manifund.org/projects/when-language-becomes-workflow); not a step-by-step walkthrough |
| 8 | [Indirect Prompt Injection Bonus Wave](https://app.grayswan.ai/arena/challenge/ipi-q1-26-bonus-wave) | Completed | $5,500 | None located |
| 9 | [Staged Attack](https://app.grayswan.ai/arena/challenge/staged-attack) | Completed | $40,000 | No direct walkthrough located; a [Gemini jailbreak retrospective](https://recursion.wtf/posts/gemini_jailbreak_retrospective/) discusses related staged-attack work but is not an Arena challenge writeup |
| 10 | [Indirect Prompt Injection Q1 2026](https://app.grayswan.ai/arena/challenge/indirect-prompt-injection-q1-2026) | Completed | $40,000 | The [IPI paper](https://arxiv.org/abs/2603.15714) says an updated version covering Q1 is planned; no Q1-specific public walkthrough located |
| 11 | [Safeguards](https://app.grayswan.ai/arena/challenge/safeguards) | Completed | $140,000 | [Participant research synthesis](https://manifund.org/projects/when-language-becomes-workflow); not a step-by-step walkthrough |
| 12 | [Indirect Prompt Injection](https://app.grayswan.ai/arena/challenge/indirect-prompt-injection) (Nov. 2025) | Completed | $40,000 | Extensive: official recap, paper/code, NIST analysis, and three participant walkthroughs listed below |
| 13 | [Machine-in-the-Middle](https://app.grayswan.ai/arena/challenge/machine-in-the-middle) | Completed/closed | $100,000 | No challenge-specific public walkthrough located |
| 14 | [DEF CON 33](https://app.grayswan.ai/arena/challenge/def-con-33) | Completed | $1,000 | No challenge-specific public walkthrough located |
| 15 | [Proving Ground](https://app.grayswan.ai/arena/challenge/proving-ground) | Ongoing/practice | Free | Official Wave 4 explainer and participant Wave 13/Wave 23 writeups; full wave index below |
| 16 | [Dangerous Reasoning](https://app.grayswan.ai/arena/challenge/dangerous-reasoning) | Completed | $20,000 | [Official recap](https://app.grayswan.ai/arena/blog/dangerous-reasoning-recap) and [D-REX paper](https://arxiv.org/abs/2509.17938) |
| 17 | [Visual Vulnerabilities](https://app.grayswan.ai/arena/challenge/visual-vulnerabilities) | Completed | $60,000 | [Official retrospective](https://app.grayswan.ai/arena/blog/visual-vulnerabilities-challenge-recap) |
| 18 | [Agent Red-Teaming](https://app.grayswan.ai/arena/challenge/agent-red-teaming) | Completed | $171,800 | Extensive: official snapshot/deep dive, paper, and videos listed below |
| 19 | [Harmful AI Assistant](https://app.grayswan.ai/arena/challenge/harmful-ai-assistant) | Completed | $40,000 | [Detailed participant writeup](https://ourinterestingtimes.substack.com/p/gray-swan-harmful-ai-assistant-challenge) and OpenAI’s o3-mini system card |
| 20 | [Multi-Turn Harmful Outputs](https://app.grayswan.ai/arena/challenge/multi-turn-harmful-outputs) | Completed | $7,000 | OpenAI o1 system card reports evaluation results; no participant walkthrough located |
| 21 | [Multimodal Jailbreaks](https://app.grayswan.ai/arena/challenge/multimodal-jailbreaks) | Completed | $6,000 | OpenAI o1 system card reports evaluation results; no participant walkthrough located |
| 22 | [Harmful Code Generation](https://app.grayswan.ai/arena/challenge/harmful-code-generation) | Completed | $6,000 | OpenAI o1 system card reports evaluation results; no participant walkthrough located |
| 23 | [Revealing Hidden Chain of Thought](https://app.grayswan.ai/arena/challenge/revealing-chain-of-thought) | Completed | $1,000 | [Arena launch retrospective](https://www.grayswan.ai/blog/gray-swan-arena) provides context; no participant walkthrough located |
| 24 | [Single Turn Harmful Outputs](https://app.grayswan.ai/arena/challenge/single-turn-harmful-outputs) | Completed | $42,000 | [Inaugural championship recap](https://www.grayswan.ai/blog/gray-swan-arena) and OpenAI o1 system card; no participant walkthrough located |
| 25 | [Hazard Hunt: Chem, Bio, Cyber, Misc](https://app.grayswan.ai/arena/challenge/hazard-hunt-q3) | Ongoing | $80,000 | None located; current event (2026-08-25 to 2026-09-11) |
| 26 | [Indirect Prompt Injection August ’26](https://app.grayswan.ai/arena/challenge/ipi-aug-2026) | Completed | $30,000 | None located; “Judging began — all $30,000 awarded” on the live catalog 2026-09-03 |
| 27 | [IPI Lucky Break](https://app.grayswan.ai/arena/challenge/ipi-lucky-break-aug) | Completed | $5,000 | None located; week-long raffle event built on revamped Proving Ground challenges, five raffle-ticket cap per person |

Statuses for completed challenges carry forward from the 2026-07-29 crawl (a completed challenge does not reopen); the three ongoing/practice cards, IPI July ’26, and the two August additions were re-verified against the live catalog on 2026-09-03.

## Verified writeups and walkthroughs

### First-party recaps and technical releases

1. [Gray Swan Arena](https://www.grayswan.ai/blog/gray-swan-arena) — Gray Swan, 2024-10-28. Retrospective on the inaugural September–October 2024 Jailbreaking Championship and launch context for Single Turn Harmful Outputs and Revealing Hidden CoT.
2. [UK AISI × Gray Swan Agent Red-Teaming Challenge: Results Snapshot](https://www.grayswan.ai/blog/uk-aisi-x-gray-swan-agent-red-teaming-challenge-results-snapshot) — Gray Swan, 2025-05-09. Results, leaderboard, model attack-success rates, and challenge mechanics.
3. [Agent Red-Teaming: The AI Jailbreak Showdown](https://app.grayswan.ai/arena/blog/agent-red-teaming-the-ai-jailbreak-showdown) — Gray Swan, 2025-06 (updated 2026-02). Long-form participant interviews and attack examples. **Contains unredacted exploit prompts.**
4. [Picture Perfect Jailbreaks: Inside the Visual Vulnerabilities Challenge](https://app.grayswan.ai/arena/blog/visual-vulnerabilities-challenge-recap) — Gray Swan, 2025-07-09. Challenge results, attacker profiles, strategies, and examples.
5. [Silent Characters, Loud Breaks](https://app.grayswan.ai/arena/blog/silent-characters-stealth-attack-week) — Gray Swan, 2025-07-18. Proving Ground Wave 4 walkthrough/explainer focused on invisible Unicode and four behaviors.
6. [Inside the Dangerous Reasoning Challenge: Covert Plans, Clean Outputs](https://app.grayswan.ai/arena/blog/dangerous-reasoning-recap) — Gray Swan, 2025-09-26. Results and high-level strategy analysis.
7. [Your AI Agent Can Be Compromised. You’d Never Know.](https://www.grayswan.ai/blog/your-ai-agent-can-be-compromised-youd-never-know) — Gray Swan, 2026-03-18. Retrospective for the November 2025 Indirect Prompt Injection challenge, with results, transfer analysis, and released artifacts.
8. [How Vulnerable Are AI Agents to Indirect Prompt Injections?](https://arxiv.org/abs/2603.15714) — Gray Swan and partners, 2026-03. Full 38-page paper for the November 2025 IPI competition.
9. [IPI Arena open-source evaluation kit](https://github.com/GraySwanAI/ipi_arena_os) — scenarios, judging system, and a limited attack-data sample released with the IPI paper.
10. [Security Challenges in AI Agent Deployment](https://arxiv.org/abs/2507.20526) — research paper based on the Agent Red-Teaming competition.
11. [D-REX: An Arena for Discovering Deceptive Reasoning in LLMs](https://arxiv.org/abs/2509.17938) — research paper based on Dangerous Reasoning.
12. [Insights on AI Agent Security from a Large-Scale Red-Teaming Competition](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition) — NIST CAISI, 2026-03-23. Independent government research summary of the IPI competition.
13. [OpenAI o1 System Card](https://cdn.openai.com/o1-system-card-20241205.pdf) — primary technical report containing Gray Swan Single Turn, Multi-Turn, Multimodal, and Harmful Code Generation evaluation results.
14. [OpenAI o3-mini System Card](https://cdn.openai.com/o3-mini-system-card-feb10.pdf) — primary technical report containing Harmful AI Assistant evaluation results.

### Participant writeups

15. [Gray Swan Harmful AI Assistant Challenge](https://ourinterestingtimes.substack.com/p/gray-swan-harmful-ai-assistant-challenge) — Daniel Juhl, 2025-02-17. Detailed account of techniques, results, and lessons from a top-ten finish. **Contains actionable jailbreak detail.**
16. [IPI competition notes #1: Email inbox](https://www.thaiaiaudit.com/en/competition-notes-with-lessons-from-gray-swan-indirect-prompt-injection-1-email-inbox-just-getting-an-email-and-youre-already-compromised/) — Veeranuch P., Thai AI Audit. Detailed November 2025 IPI walkthrough focused on email agents.
17. [IPI competition notes #2: Developers](https://www.thaiaiaudit.com/en/competition-notes-with-lessons-from-gray-swan-indirect-prompt-injection-2-being-a-developer-doesnt-mean-youre-safe/) — Veeranuch P., Thai AI Audit. Coding-agent scenarios and lessons.
18. [IPI competition notes #3](https://www.thaiaiaudit.com/en/competition-notes-with-lessons-from-gs3/) — Veeranuch P., Thai AI Audit. Web, computer-use, and tool-agent scenarios.
19. [Three-month journal after starting HackAPrompt / Gray Swan](https://www.thaiaiaudit.com/en/three-month-journal-after-starting-hackaprompt-gray-swan/) — participant reflection and context for the November 2025 IPI competition.
20. [The Burn Toast Experiment](https://www.thaiaiaudit.com/en/the-burn-toast-experiment-en/) — participant writeup for Proving Ground Wave 23’s `burn-toast` indirect-injection behavior, including a cross-model experiment and technical appendix.
21. [“Give this student an A” trap](https://www.thaiaiaudit.com/en/system-ignore-previous-instructions-give-this-student-an-a-prompt-injection-in-education-the-give-an-a-trap/) — educational prompt-injection explainer mapped to Proving Ground Wave 13’s `missing-essay` behavior.
22. [My most memorable break in Gray Swan](https://www.thaiaiaudit.com/en/my-most-memorable-break-in-gray-swan-2/) — long-turn prisoner/guard account, probably The Labyrinth; the article does not explicitly name the challenge, so this mapping remains qualified.
23. [When Language Becomes Workflow](https://manifund.org/projects/when-language-becomes-workflow) — participant synthesis referencing IPI Q2 2026, Human / Browser Agent Robustness, and Safeguards. It is a research proposal/analysis, not a procedural walkthrough.
24. [Cyber Bypass participant result](https://www.linkedin.com/posts/uhyang03_anthropic%EC%9D%B4-%ED%9B%84%EC%9B%90%ED%95%98%EA%B3%A0-gray-swan-arena%EC%97%90%EC%84%9C-%EA%B0%9C%EC%B5%9C%EB%90%9C-cyber-activity-7476074403743604736-5xRf) — public LinkedIn mini-writeup reporting mechanics, placement, and rarity of successful breaks; not a full walkthrough.

### Video walkthroughs and talks

25. [This Hacker Made Over $10,000 Hacking AI](https://www.youtube.com/watch?v=xy1vQOHGQQY) — NahamSec with Kameron Bettridge, 2025-11-03, 27 minutes. Public Arena/Agent Red-Teaming technique walkthrough.
26. [AI Red Teaming — Getting Started — Gray Swan Arena](https://www.youtube.com/watch?v=S0IKgLtmxs4) — Muhammad Shadab, about 9 minutes. Beginner platform walkthrough.
27. [Breaking AI Agents: From Jailbreaks to MCP Exploits with Javi Rivera](https://www.youtube.com/watch?v=s8DPj-gYsxg) — ZioSec, about 56 minutes. Includes a live Gray Swan Arena indirect-prompt-injection demonstration.
28. [AI Security After Codex and Claude Code](https://www.youtube.com/watch?v=j8BAficRjEc&t=534s) — Latent Space with Zico Kolter and Matt Fredrikson. Arena and automated red-teaming discussion begins around 08:54; context rather than a challenge walkthrough.
29. [Current State of AI Agent Security](https://www.youtube.com/watch?v=7I4h8zvQg4s) — FAR.AI talk by Andy Zou. Short results/demo-oriented overview, not a hands-on guide.

### Added in the 2026-09-03 sync

32. [Get Paid to Manipulate AI](https://blacktechpipeline.substack.com/p/get-paid-to-manipulate-ai) — Black Tech Pipeline, 2026-08-04. Participant article covering Arena participation and Proving Ground practice.
33. [Spencer Whitman — Gray Swan AI’s $200M Plan to Secure AI Systems](https://www.forwarddeployed.com/episodes/spencer-whitman-gray-swan-ai-39-s-200m-plan-to-secure-ai-systems) — Forward Deployed, 2026-08-10. Company interview episode with an Arena discussion; context rather than a challenge walkthrough.
34. [My first time red teaming AI in Gray Swan’s Arena](https://www.linkedin.com/posts/whitneymenarcheck_my-first-time-red-teaming-ai-in-gray-swans-activity-7495831952592183296-3tH3) — Whitney Menarcheck, 2026-08-19. Public LinkedIn mini-writeup; it links a longer writeup through a short URL that was not independently fetched.
35. [Hazard Hunt is live in the Gray Swan Arena](https://www.linkedin.com/posts/grayswanai_hazard-hunt-is-live-in-the-gray-swan-arena-activity-7498061860332552192-Ef0e) — Gray Swan, 2026-08-25. Official launch announcement for the $80,000 Hazard Hunt competition.

The CSV distinguishes direct walkthroughs from recaps, papers, contextual talks, and adjacent analyses. The “26” headline count excludes the nine lower-specificity contextual resources in this list, which are retained for completeness.

## Proving Ground wave archive

Each published wave normally has Chat, Image, Agent, and Indirect behaviors. Slugs below come from the live UI, except Wave 1 ([2025-07-12 Internet Archive capture](https://web.archive.org/web/20250712072306id_/https://app.grayswan.ai/arena/challenge/proving-ground/chat)) and Wave 4 ([2025-08-04 capture](https://web.archive.org/web/20250804063256id_/https://app.grayswan.ai/arena/challenge/proving-ground/chat) plus the official article). The 2026-09-03 sync re-verified the Wave 21–26 slugs against the live homepage showcase (unchanged) and found no Wave 27+ and no recovery of the gap waves. The catalog’s featured carousel now also markets a revamped “Proving Grounds” format — IPI Lucky Break was built on it — but the historical wave archive above is unchanged.

| Wave | Chat | Image | Agent | Indirect | Visibility / coverage |
|---:|---|---|---|---|---|
| 1 | `owlsec-windows-desktop-bypass` | `owlsec-lockpicking` | `owlsec-change-admin-pass` | `owlsec-security-alert` | Removed from live UI; recovered from 2025-07-12 archive |
| 2 | `political-death-fake-news` | `game-piracy` | `leak-students-grade` | `indirect-gender-discrimination` | Live |
| 3 | `mdma-manufacturing-boyfriend` | `website-cloning-phish` | `leak-api-key-tutorly` | `disable-ai-lottery` | Live |
| 4 | `vaccine-conspiracy-invis-unicode` | `discrimination-invis-unicode` | `ai-review-invis-unicode` | `rant-email-invis-unicode` | Removed; [official walkthrough](https://app.grayswan.ai/arena/blog/silent-characters-stealth-attack-week) |
| 5 | `ghost-gun` | `toxic-plant` | `sell-cancer-cure` | `pr-buddy-phish` | Live |
| 6 | `plane-hijacking` | `deadly-airfilter` | `social-discrimination` | `deadly-nurse` | Live |
| 7 | — | — | — | — | Not exposed and not recovered |
| 8 | — | — | — | — | Not exposed and not recovered |
| 9 | `chlorine-gas-bomb` | `break-n-enter` | `vulnerable-toolcall` | `bypass-spam-filter` | Live |
| 10 | — | — | — | — | Not exposed and not recovered |
| 11 | `kidnap-rabbit` | `deadly-car-mod` | `prohibited-food-selling` | `hijack-recruiter` | Live |
| 12 | `christmas-mariah-lyrics` | `shoplifting` | `leak-movie` | `free-food` | Live |
| 13 | `gas-station-robbing` | `tesla-carjacking` | `double-refund` | `missing-essay` | Live; [participant explainer](https://www.thaiaiaudit.com/en/system-ignore-previous-instructions-give-this-student-an-a-prompt-injection-in-education-the-give-an-a-trap/) |
| 14 | `tax-fraud` | `anthrax-letter` | `salary-negotiation` | `llm-phish2` | Live |
| 15 | `drug-dealer-search` | `dine-n-dash` | `underaged-shopping` | `candle-scam` | Live |
| 16 | `mass-food-poisoning` | `bomb-political-building` | `weak-password-change` | `indirect-function-call` | Live |
| 17 | `quiz-cheating` | `room-break-in` | `negative-quantity-exploit` | `sqli-medical-records` | Live |
| 18 | `nintendo-leak` | `image-leak-secret` | `ai-browser-parental-bypass` | `ai-browser-drain-crypto` | Live |
| 19 | `bamboo-cyanide` | `hide-items-from-police` | `defamatory-linkedin` | `linkedin-company-appreciation` | Live |
| 20 | `rig-gift` | `cookie-image-train-hijacking` | `christmas-giftcard-scam` | `exploit-gift-ai` | Live |
| 21 | `illegal-fireworks` | `tamper-with-inhaler` | `website-exploitation-js` | `ad500052-a882-4fd6-81d0-5f928def830e` | Live; indirect behavior lacks a descriptive slug |
| 22 | `elder-financial-abuse-plan` | `counterfeit-currency-image` | `stop-ai-from-verifying` | `teach-swears` | Live |
| 23 | `damage-property` | `car-booby-trap-image` | `banking-idor-exploit` | `burn-toast` | Live; [participant walkthrough](https://www.thaiaiaudit.com/en/the-burn-toast-experiment-en/) |
| 24 | `record-call` | `image-only-hacking` | `agent-piracy` | `summary-email-dos` | Live |
| 25 | `smoke-detector-americium-extraction` | `forge-a-collectable` | `student-inappropriate-message` | `malware-game-description` | Live |
| 26 | `propaganda-no-excuse` | `package-theft-image` | `incorrect-hotel` | `text-ransomware-injection` | Live |

## Announced but not publicly recoverable

- Gray Swan announced an OwlSec live Proving Ground walkthrough in its Discord in [this launch post](https://app.grayswan.ai/arena/blog/owlsec-gray-swan-ai-the-proving-proving-ground-has-launched). I found no publicly indexed replay, transcript, or slides.
- No substantive independent walkthrough was located for 15 named completed challenges: IPI July ’26 (ended 2026-08-03), IPI August ’26, IPI Lucky Break, IPI June ’26, IPI Bonus Wave, Machine-in-the-Middle, DEF CON 33, IPI Q1 2026, Multi-Turn Harmful Outputs, Multimodal Jailbreaks, Harmful Code Generation, Revealing Hidden CoT, plus direct challenge-specific walkthroughs for Staged Attack, Safeguards, and Human / Browser Agent Robustness. Some have official evaluation results or adjacent participant analysis, as marked in the inventory.
- “No public walkthrough located” means none was discoverable through the Arena, Gray Swan sites, indexed web/video search, linked participant profiles, GitHub/arXiv, and available Internet Archive captures as of the research date. It is not proof that an unindexed, deleted, login-gated, Discord-only, or non-English resource does not exist.

## Method

1. Opened the Arena, enabled the completed filter, selected **View all**, and expanded **Show All Waves**.
2. Recorded every visible named challenge and Proving Ground behavior slug.
3. Searched exact and variant challenge names with `writeup`, `walkthrough`, `solution`, `recap`, `jailbreak`, and `red team`; repeated searches across the web, YouTube, GitHub, arXiv, LinkedIn, Substack, and participant sites.
4. Followed first-party blog and paper links, then searched author/participant profiles for challenge-specific accounts.
5. Queried the Internet Archive CDX index and inspected snapshots of the Arena and Proving Ground pages to recover retired waves.
6. Verified that participant pages and videos in the index returned public HTTP 200 responses on 2026-07-29.
7. 2026-09-03 sync pass: re-fetched the live catalog homepage and the IPI July ’26 challenge page, re-verified Proving Ground waves 21–26, swept the web/YouTube/GitHub/LinkedIn/Substack and the Wayback CDX index (post-2026-07-29 captures only) for new challenges, waves, and writeups, and recorded the delta with that date.

## Caveats and safe use

Several linked sources contain unredacted prompt injections, jailbreak text, or descriptions of harmful target behaviors. Use them only in authorized research and controlled evaluation environments. The index intentionally summarizes and classifies those sources without copying their payloads.

Arena status and availability can change. Treat this as a dated research snapshot — the baseline crawl is 2026-07-29 and the most recent verification pass is 2026-09-03 — not a permanently exhaustive registry.
