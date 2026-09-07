# Example Project Specification

## 1. Hardware Module (top.v)
- Clock: `clk`
- Reset: `rst`
- Data Input: `data_in`
- Data Output: `data_out`
- Security Requirement: State sequence must not reach crash state 3.

## 2. Backend Services
- Python service requires input sanitization.
- Java auth token parser must not deserialize arbitrary objects.
- Go API keys must not be checked into source code.
- Native C/C++ routines must validate buffer bounds before copying.
