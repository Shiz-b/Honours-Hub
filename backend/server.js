const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key'; //  use environment variable latr on

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('../frontend'));

// Data file paths
const DATA_DIR = path.join(__dirname, 'data');
const STUDENTS_FILE = path.join(DATA_DIR, 'students.json');
const ACADEMICS_FILE = path.join(DATA_DIR, 'academics.json');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');
const APPLICATIONS_FILE = path.join(DATA_DIR, 'applications.json');
const MEETINGS_FILE = path.join(DATA_DIR, 'meetings.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initialize JSON files if they don't exist
const initializeFile = (filePath, initialData = []) => {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, JSON.stringify(initialData, null, 2));
    }
};

initializeFile(STUDENTS_FILE);
initializeFile(ACADEMICS_FILE);
initializeFile(PROJECTS_FILE);
initializeFile(APPLICATIONS_FILE);
initializeFile(MEETINGS_FILE);

// Helper functions
const readJsonFile = (filePath) => {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
};

const writeJsonFile = (filePath, data) => {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
};

const generateId = () => {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Register student
app.post('/api/register/student', async (req, res) => {
    try {
        const { firstName, lastName, degree, yearOfStudy, email, password } = req.body;
        
        // Check if student already exists
        const students = readJsonFile(STUDENTS_FILE);
        const existingStudent = students.find(s => s.email === email);
        
        if (existingStudent) {
            return res.status(400).json({ error: 'Student with this email already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create new student
        const newStudent = {
            id: generateId(),
            firstName,
            lastName,
            degree,
            yearOfStudy,
            email,
            password: hashedPassword,
            profilePicture: null,
            createdAt: new Date().toISOString()
        };
        
        students.push(newStudent);
        writeJsonFile(STUDENTS_FILE, students);
        
        res.status(201).json({ message: 'Student registered successfully', studentId: newStudent.id });
    } catch (error) {
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// Register academic
app.post('/api/register/academic', async (req, res) => {
    try {
        const { name, email, password, faculty, school } = req.body;
        
        // Check if academic already exists
        const academics = readJsonFile(ACADEMICS_FILE);
        const existingAcademic = academics.find(a => a.email === email);
        
        if (existingAcademic) {
            return res.status(400).json({ error: 'Academic with this email already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create new academic
        const newAcademic = {
            id: generateId(),
            name,
            email,
            password: hashedPassword,
            faculty,
            school,
            profilePicture: null,
            createdAt: new Date().toISOString()
        };
        
        academics.push(newAcademic);
        writeJsonFile(ACADEMICS_FILE, academics);
        
        res.status(201).json({ message: 'Academic registered successfully', academicId: newAcademic.id });
    } catch (error) {
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Check students first
        const students = readJsonFile(STUDENTS_FILE);
        const student = students.find(s => s.email === email);
        
        if (student) {
            const isValidPassword = await bcrypt.compare(password, student.password);
            if (isValidPassword) {
                const token = jwt.sign(
                    { id: student.id, email: student.email, role: 'student' },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );
                return res.json({ 
                    token, 
                    user: { 
                        id: student.id, 
                        email: student.email, 
                        role: 'student',
                        name: `${student.firstName} ${student.lastName}`
                    } 
                });
            }
        }
        
        // Check academics
        const academics = readJsonFile(ACADEMICS_FILE);
        const academic = academics.find(a => a.email === email);
        
        if (academic) {
            const isValidPassword = await bcrypt.compare(password, academic.password);
            if (isValidPassword) {
                const token = jwt.sign(
                    { id: academic.id, email: academic.email, role: 'academic' },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );
                return res.json({ 
                    token, 
                    user: { 
                        id: academic.id, 
                        email: academic.email, 
                        role: 'academic',
                        name: academic.name
                    } 
                });
            }
        }
        
        res.status(401).json({ error: 'Invalid email or password' });
    } catch (error) {
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
    try {
        if (req.user.role === 'student') {
            const students = readJsonFile(STUDENTS_FILE);
            const student = students.find(s => s.id === req.user.id);
            if (student) {
                const { password, ...studentData } = student;
                return res.json(studentData);
            }
        } else if (req.user.role === 'academic') {
            const academics = readJsonFile(ACADEMICS_FILE);
            const academic = academics.find(a => a.id === req.user.id);
            if (academic) {
                const { password, ...academicData } = academic;
                return res.json(academicData);
            }
        }
        
        res.status(404).json({ error: 'User not found' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all projects (for student library)
app.get('/api/projects', authenticateToken, (req, res) => {
    try {
        const projects = readJsonFile(PROJECTS_FILE);
        res.status(200).json(projects);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all students (for academic view)
app.get('/api/students', authenticateToken, (req, res) => {
    try {
        if (req.user.role !== 'academic') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const students = readJsonFile(STUDENTS_FILE);
        const studentsWithoutPasswords = students.map(student => {
            const { password, ...studentData } = student;
            return studentData;
        });
        
        res.json(studentsWithoutPasswords);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create project (academic only)
app.post('/api/projects', authenticateToken, (req, res) => {
    try {
        if (req.user.role !== 'academic') {
            return res.status(403).json({ error: 'Only academics can create projects' });
        }
        
        const { title, description, requirements, duration } = req.body;
        const projects = readJsonFile(PROJECTS_FILE);
        
        const newProject = {
            id: generateId(),
            title,
            description,
            requirements,
            duration,
            academicId: req.user.id,
            createdAt: new Date().toISOString(),
            status: 'open'
        };
        
        projects.push(newProject);
        writeJsonFile(PROJECTS_FILE, projects);
        
        res.status(201).json({ message: 'Project created successfully', project: newProject });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Apply to project (student only)
app.post('/api/apply/:projectId', authenticateToken, (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Only students can apply to projects' });
        }
        
        const { projectId } = req.params;
        const { message } = req.body;
        const applications = readJsonFile(APPLICATIONS_FILE);
        
        // Check if already applied
        const existingApplication = applications.find(app => 
            app.projectId === projectId && app.studentId === req.user.id
        );
        
        if (existingApplication) {
            return res.status(400).json({ error: 'Already applied to this project' });
        }
        
        const newApplication = {
            id: generateId(),
            projectId,
            studentId: req.user.id,
            message,
            status: 'pending',
            appliedAt: new Date().toISOString()
        };
        
        applications.push(newApplication);
        writeJsonFile(APPLICATIONS_FILE, applications);
        
        res.status(201).json({ message: 'Application submitted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get applications (role-based)
app.get('/api/applications', authenticateToken, (req, res) => {
    try {
        const applications = readJsonFile(APPLICATIONS_FILE);
        
        if (req.user.role === 'student') {
            const studentApplications = applications.filter(app => app.studentId === req.user.id);
            res.json(studentApplications);
        } else if (req.user.role === 'academic') {
            const projects = readJsonFile(PROJECTS_FILE);
            const academicProjects = projects.filter(p => p.academicId === req.user.id);
            const academicProjectIds = academicProjects.map(p => p.id);
            const academicApplications = applications.filter(app => 
                academicProjectIds.includes(app.projectId)
            );
            res.json(academicApplications);
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
