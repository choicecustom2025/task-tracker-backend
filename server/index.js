const express = require('express');
const mongoose = require('mongoose'); // ✅ only once
const cors = require('cors');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth');
const taskRoutes = require('./routes/tasks');
