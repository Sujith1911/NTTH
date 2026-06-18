# NTTH Final Year Project Report Draft Plan

Target: 80+ pages with figures, tables, screenshots, diagrams, code excerpts, references, and appendices.

Project: NTTH - Network Threat Trap and Honeypot / autonomous network threat detection and response pipeline.

## Practical File/Page Limit

There is no fixed limit on how many documentation files I can create in this workspace. The better limit is practical:

- I can create and maintain many Markdown, HTML, DOCX-ready, or LaTeX-style files.
- A single 80+ page report is possible, but it is safer to build it chapter-by-chapter.
- Very long files are harder to review, regenerate, and fix, so the recommended structure is multiple chapter source files plus one merged final document.
- Images, diagrams, tables, and screenshots can be included from `docs/thesis_images/` and generated assets.
- The final output can be prepared as HTML/PDF/DOCX depending on your college submission requirement.

Recommended structure:

- `docs/report_final/00_preliminaries.md`
- `docs/report_final/01_introduction.md`
- `docs/report_final/02_srs.md`
- `docs/report_final/03_design.md`
- `docs/report_final/04_coding.md`
- `docs/report_final/05_conclusion.md`
- `docs/report_final/06_references.md`
- `docs/report_final/appendices.md`
- `docs/report_final/assets/`
- `docs/report_final/NTTH_Final_Project_Report.pdf`

## Required College Format Mapping

The uploaded format requires:

- Cover page print out
- Acknowledgement
- Abstract
- Table of Contents
- List of Figures
- Chapter 1: Introduction
- Chapter 2: Requirements Elicitation and Analysis / SRS
- Chapter 3: Design Specification
- Chapter 4: Coding
- Chapter 5: Conclusion
- Future Scope
- References

Preliminary pages should use Roman numbering, such as `i, ii, iii, iv`.
Main content should use numeric page numbering, such as `1, 2, 3`.

## Proposed 80+ Page Allocation

| Section | Target Pages | Notes |
|---|---:|---|
| Cover Page | 1 | College/project details |
| Acknowledgement | 1 | Formal acknowledgement |
| Abstract | 1 | 250-350 words |
| Table of Contents | 2 | Auto-generated if possible |
| List of Figures | 2 | Include all diagrams/screenshots |
| Chapter 1: Introduction | 10-12 | Background, motivation, objectives, problem definition, requirements |
| Chapter 2: SRS | 12-14 | Purpose, scope, stakeholders, functional/non-functional requirements, technologies |
| Chapter 3: Design Specification | 24-28 | Architecture, DFD, ER, sequence, use case, activity, database, PERT/Gantt, UI screens |
| Chapter 4: Coding | 14-18 | Key modules, algorithms, flowcharts, selected code listings |
| Chapter 5: Conclusion | 5-7 | Summary, limitations, future scope |
| References | 3-5 | IEEE-style references |
| Appendices | 6-10 | Extra screenshots, setup commands, test cases, sample logs |
| Total | 81-101 | Allows room for images and tables |

## Chapter 1: Introduction

Target: 10-12 pages.

### 1.1 Introduction

Content:

- Network security background
- Growth of wireless and LAN-based threats
- Need for real-time defensive monitoring
- Why alert-only systems are insufficient
- Why commodity hardware deployment matters
- Project overview: NTTH as an autonomous defensive pipeline

Suggested figures:

- `docs/thesis_images/fig1_1_detection_response_gap.png`
- `docs/thesis_images/fig_topology.png`

### 1.2 Objective(s) of the Proposed System

Content:

- Detect suspicious network behavior
- Score threats using hybrid/ML-based logic
- Trigger response automatically
- Redirect suspicious activity toward honeypot components
- Provide dashboard visibility
- Evaluate detection and response performance

Suggested table:

- Objectives vs measurable outcomes

### 1.3 Present System Description

Content:

- Existing IDS/IPS systems
- Snort and Suricata style alerting
- Traditional static honeypots
- Manual administrator response workflow
- Limitations in small lab or commodity environments

Suggested table:

- Existing system vs proposed system

### 1.4 Problem Definition of the Proposed System

Content:

- Delayed response after detection
- Lack of flow-aware honeypot redirection
- Limited validation on real packets
- Need for explainable metrics: latency, false positives, detection rate

### 1.5 Hardware and Software Requirements

Content:

- Ubuntu laptop
- Atheros AR9271 USB WiFi adapter
- Mobile phone with Termux
- Python services
- Flutter dashboard
- nftables/firewall rules
- ML libraries and datasets

Suggested table:

- Hardware requirements
- Software requirements

## Chapter 2: Requirements Elicitation and Analysis / SRS

Target: 12-14 pages.

### 2.1 Introduction

Content:

- SRS purpose
- Scope of the report section
- Intended users: administrator, researcher, evaluator
- Controlled lab assumptions

### 2.1.1 Purpose

Content:

- Define expected system behavior
- Document detection, scoring, response, logging, and dashboard requirements
- Clarify defensive-only use

### 2.1.2 Scope

Content:

- Passive WiFi/network monitoring
- Threat scoring
- Automated response
- Honeypot deployment/redirect
- Dashboard and reporting
- Experiment evaluation

Out of scope:

- Offensive exploitation
- Unauthorized network monitoring
- Production enterprise deployment without hardening

### 2.1.3 Technologies to be Used

Content:

- Python
- Scapy/packet capture tooling
- Isolation Forest and comparison ML models
- nftables/Linux firewall
- Flutter dashboard
- SQLite or project database layer
- CICIDS2017 benchmark

Suggested tables:

- Technology stack
- Functional requirements
- Non-functional requirements
- User requirements
- System constraints

## Chapter 3: Design Specification

Target: 24-28 pages.

### 3.1 Architecture Design

Content:

- High-level NTTH architecture
- Monitoring component
- Feature extraction
- Threat scoring
- Decision engine
- Response engine
- Honeypot logic
- Dashboard

Suggested figures:

- `docs/thesis_images/fig3_1_system_architecture.png`
- `docs/thesis_images/fig3_2_agent_pipeline_flow.png`
- `docs/thesis_images/fig3_3_async_event_bus_topology.png`

### 3.2 Data Flow Diagram

Content:

- Level 0 context diagram
- Level 1 process flow
- Packet capture to dashboard flow

Suggested figure:

- New DFD diagram if not already present.

### 3.3 Class Diagram / ER Diagram

Content:

- Main classes/modules
- Entity relationships for alerts, packets, devices, honeypot events, responses

Suggested figure:

- `docs/thesis_images/fig3_6_database_er_diagram.png`

### 3.4 Sequence Diagram

Content:

- Packet observed
- Feature extraction
- Threat scoring
- Decision
- Firewall/honeypot action
- Dashboard update

Suggested figure:

- New sequence diagram.

### 3.5 Use Case Diagram

Content:

- Admin views dashboard
- System monitors traffic
- System detects threat
- System triggers response
- Admin reviews logs
- Researcher exports metrics

Suggested figure:

- New use case diagram.

### 3.6 Activity Diagram

Content:

- Monitoring loop
- Scoring branch
- Response branch
- Logging and feedback branch

Suggested figure:

- New activity diagram.

### 3.7 Database Design

Content:

- Tables/entities
- Primary keys and relationships
- Data dictionary
- Sample schema explanation

Suggested tables:

- Database table descriptions
- Field-level data dictionary

### 3.8 Project Estimation and Implementation Plan

Content:

- Work breakdown structure
- Module estimates
- Risk areas
- Milestones

### 3.8.1 PERT Chart

Content:

- Task dependency chart
- Critical path explanation

Suggested figure:

- New PERT chart.

### 3.8.2 Gantt Chart

Content:

- Week-wise project implementation schedule

Suggested figure:

- New Gantt chart.

### 3.9 Input and Output Screen Design Preview

Content:

- Login screen
- Dashboard screen
- Device list
- Threat map
- Firewall/response screen
- Honeypot screen

Suggested figures:

- `docs/thesis_images/fig_login.png`
- `docs/thesis_images/fig_dashboard.png`
- `docs/thesis_images/fig_devices.png`
- `docs/thesis_images/fig_threatmap.png`
- `docs/thesis_images/fig_firewall.png`
- `docs/thesis_images/fig_honeypot.png`

## Chapter 4: Coding

Target: 14-18 pages.

### 4.1 Code / Program Listing

Content:

- Only important code excerpts, not full source dump
- Packet capture module
- Feature extraction module
- Threat scoring module
- ML model training/evaluation module
- Response/firewall module
- Honeypot routing module
- Dashboard API or state update module

Suggested format:

- Short explanation before each listing
- 20-45 lines per listing
- Caption for each listing

### 4.2 Algorithm / Flowchart

Content:

- Overall NTTH algorithm
- Threat scoring algorithm
- Response decision algorithm
- Honeypot deployment algorithm
- Feedback/adaptation loop if implemented

Suggested figures:

- Flowchart for detection-to-response cycle
- Flowchart for ML scoring pipeline

## Chapter 5: Conclusion

Target: 5-7 pages.

### 5.1 Summary

Content:

- What the project built
- Major modules completed
- Defensive contribution
- Evaluation summary: detection, latency, false positive rate, comparison results

### 5.2 Limitations of the Project

Content:

- Controlled lab environment
- Commodity hardware limitations
- Dataset generalization limits
- Model retraining requirements
- Need for broader network testing

## Future Scope

Target: 2-3 pages.

Content:

- Larger testbed deployment
- More attack categories
- More robust feedback learning
- Cloud dashboard
- SIEM integration
- Additional wireless monitoring features
- More datasets and cross-environment testing

## References

Target: 3-5 pages.

Content:

- IEEE-style references
- Include related work from research preferences:
  - AARF
  - AETHER
  - LLM Agent Honeypot
  - Snort
  - Suricata
  - CICIDS2017
  - Isolation Forest
  - Network IDS/honeypot references

## Figure Plan

Minimum recommended figures: 22-30.

| Figure No. | Figure Title | Source/Status |
|---|---|---|
| 1.1 | Detection and Response Gap | Existing |
| 1.2 | NTTH Lab Network Topology | Existing |
| 3.1 | System Architecture | Existing |
| 3.2 | Agent-Inspired Pipeline Flow | Existing |
| 3.3 | Async Event Bus Topology | Existing |
| 3.4 | Packet Capture Pipeline | Existing |
| 3.5 | Honeypot Deployment Logic | Existing |
| 3.6 | Database ER Diagram | Existing |
| 3.7 | Data Flow Diagram Level 0 | To create |
| 3.8 | Data Flow Diagram Level 1 | To create |
| 3.9 | Sequence Diagram | To create |
| 3.10 | Use Case Diagram | To create |
| 3.11 | Activity Diagram | To create |
| 3.12 | PERT Chart | To create |
| 3.13 | Gantt Chart | To create |
| 3.14 | Login Screen | Existing |
| 3.15 | Dashboard Screen | Existing |
| 3.16 | Devices Screen | Existing |
| 3.17 | Threat Map Screen | Existing |
| 3.18 | Firewall Screen | Existing |
| 3.19 | Honeypot Screen | Existing |
| 4.1 | Detection Algorithm Flowchart | To create |
| 4.2 | Response Algorithm Flowchart | To create |
| 5.1 | Response Time Distribution | Existing |
| 5.2 | Comparative Result Bar Chart | Existing |

## Table Plan

Minimum recommended tables: 14-18.

| Table No. | Table Title |
|---|---|
| 1.1 | Existing System vs Proposed System |
| 1.2 | Hardware Requirements |
| 1.3 | Software Requirements |
| 2.1 | Stakeholder Requirements |
| 2.2 | Functional Requirements |
| 2.3 | Non-Functional Requirements |
| 2.4 | Technology Stack |
| 2.5 | Use Case Summary |
| 3.1 | Module Description |
| 3.2 | Database Table Summary |
| 3.3 | Data Dictionary |
| 3.4 | Project Milestones |
| 3.5 | Risk and Mitigation Plan |
| 4.1 | Important Source Modules |
| 4.2 | Algorithm Inputs and Outputs |
| 5.1 | Result Summary |
| 5.2 | Limitations and Mitigations |
| R.1 | Research Paper Comparison |

## Existing Project Assets to Reuse

Useful source files already present:

- `docs/NTTH Thesis Document.pdf`
- `docs/THESIS_DOCUMENT.html`
- `docs/thesis_part1_preliminary.html`
- `docs/thesis_part2_introduction.html`
- `docs/thesis_part3_literature.html`
- `docs/thesis_part4_design.html`
- `docs/thesis_part5_implementation.html`
- `docs/thesis_part6_testing.html`
- `docs/thesis_part7_conclusion.html`
- `docs/NTTH_COMPLETE_SYSTEM_GUIDE.md`
- `docs/IEEE_NTTH_RESEARCH_PAPER.md`
- `docs/SPRINGER_NTTH_RESEARCH_PAPER.md`
- `docs/RESEARCH_PREFERENCES.md`
- `docs/thesis_images/`

## Drafting Workflow

### Phase 1: Structure

- Create final report folder.
- Create chapter files matching college format.
- Add title page, acknowledgement, abstract, TOC placeholder, list of figures placeholder.
- Add page allocation markers.

### Phase 2: Content Expansion

- Expand Chapter 1 and Chapter 2 first.
- Reuse existing thesis/project-guide content.
- Adapt research-paper language into B.Tech report language.
- Keep wording formal but simpler than IEEE paper style.

### Phase 3: Diagrams and Images

- Reuse existing PNG/SVG assets.
- Create missing diagrams:
  - DFD Level 0
  - DFD Level 1
  - Sequence diagram
  - Use case diagram
  - Activity diagram
  - PERT chart
  - Gantt chart
  - Flowcharts

### Phase 4: Coding Chapter

- Select important source files.
- Add short listings with explanation.
- Avoid dumping entire files.
- Add algorithms and flowcharts.

### Phase 5: Final Formatting

- Roman numbering for preliminary pages.
- Numeric numbering from Chapter 1.
- Consistent figure captions.
- Consistent table captions.
- References in IEEE style.
- Generate final PDF/DOCX if required.

## Recommended Next Step

Create the actual `docs/report_final/` folder and start with:

1. Preliminaries
2. Chapter 1
3. Chapter 2
4. Figure inventory

After that, continue chapter-by-chapter until the report reaches 80+ pages.
