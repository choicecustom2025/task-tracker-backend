// 📁 /server/routes/tasks.js
const express = require('express');
const Task = require('../models/Task');
const { authMiddleware, adminMiddleware } = require('../middleware/authMiddleware');
const router = express.Router();

// Create Task
router.post('/', authMiddleware, async (req, res) => {
  const newTask = new Task({ ...req.body, user: req.user.id });
  try {
    const saved = await newTask.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(400).json({ message: 'Could not create task' });
  }
});

// Get all tasks for user OR all tasks if admin
router.get('/', authMiddleware, async (req, res) => {
  try {
    const tasks = req.user.role === 'admin'
      ? await Task.find().populate('user', 'username')
      : await Task.find({ user: req.user.id });
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch tasks' });
  }
});

// Update Task
router.put('/:id', authMiddleware, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ message: 'Task not found' });
    if (req.user.role !== 'admin' && task.user.toString() !== req.user.id)
      return res.status(403).json({ message: 'Unauthorized' });

    Object.assign(task, req.body);
    await task.save();
    res.json(task);
  } catch (err) {
    res.status(500).json({ message: 'Could not update task' });
  }
});

// Delete Task
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ message: 'Task not found' });
    if (req.user.role !== 'admin' && task.user.toString() !== req.user.id)
      return res.status(403).json({ message: 'Unauthorized' });

    await task.remove();
    res.json({ message: 'Task deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Could not delete task' });
  }
});

module.exports = router;
