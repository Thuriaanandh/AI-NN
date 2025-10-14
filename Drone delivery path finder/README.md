# Drone Delivery Pathfinding: Classical Search vs Reinforcement Learning

## Project Overview
This project explores the evolution of search and learning algorithms by implementing a **Drone Delivery Pathfinding** problem. We compare classical search algorithms (DFS, BFS, A*) with modern reinforcement learning (RL) methods (Q-Learning, DQN, PPO) in a grid-world environment. The goal is to analyze the impact of **heuristics, reward shaping, and algorithmic choice** on performance and learning behavior.

---

## Environment

**DroneDeliveryEnv** simulates a drone navigating a 2D grid from a **start point** to a **goal**, avoiding obstacles and managing battery constraints.  

- **State space:** `(x, y, battery)`  
- **Action space:** `0: Up`, `1: Down`, `2: Left`, `3: Right`, `4: Hover`  
- **Reward design:**
  - Step penalty: -1
  - Collision with obstacle: -20
  - Battery depletion: -50
  - Reaching goal: +100
  - Reward shaping: +2 for moving closer to goal, -2 for moving farther
- **Termination:** Goal reached or battery depleted

---

## Algorithms Implemented

### Classical Search
- **DFS (Depth-First Search)**
- **BFS (Breadth-First Search)**
- **A\*** with Manhattan distance heuristic

### Reinforcement Learning
- **Q-Learning** (Value-based)
- **DQN (Deep Q-Network)** (Value-based)
- **PPO (Proximal Policy Optimization)** (Policy-gradient)

### Baseline / Comparison
- Random agent
- Greedy heuristic for classical search

---

## Installation & Dependencies

Python >= 3.9 recommended. Install required libraries:

```bash
pip install -r requirements.txt
