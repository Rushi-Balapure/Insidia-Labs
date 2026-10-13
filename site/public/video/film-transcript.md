# Transcript: film

## 00:00 The bug that doesn't crash

This support bot answered the question.
It also printed part of its own system prompt.
The instruction was hidden in the PDF. Nothing crashed.

## 00:20 Two layers to test

An AI app is still an app, with a new kind of input.
Anything the model reads can carry an instruction.
AI checks and app checks usually run in different tools, on different days.
The risky path can start on one side and end on the other.

## 00:50 What Insidia does

Insidia tests both layers in one run, on your machine.
It runs engines like garak, promptfoo, Nuclei, and ZAP, plus its own checks.
Every result names the engine that produced it.

## 01:15 Scope

Insidia only touches hosts you list.
Anything beyond localhost needs authorized: true, set by you.
A planted canary proves a leak. No guessing.

## 01:35 Scan

L1 is the baseline. Fast enough for every pull request.
Each row: the check, the result, the engine, the time.
A check that couldn't run is marked incomplete, never passed.

## 02:00 Report

One HTML file. Opens offline.
The attack, the reply, and the proof.
It also lists what wasn't tested.

## 02:25 Fix and rerun

Treat uploads as data, not instructions.
Rerun checks again with the same config. Now it passes.

## 02:40 CI and your coding agent

In CI, a failed policy blocks the merge.
Or hand it to your coding agent. You confirm the hosts.
Your AI agent is your newest attack surface.
