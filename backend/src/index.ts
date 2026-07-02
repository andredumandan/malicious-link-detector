import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import rateLimit from 'express-rate-limit'
import scanRoutes from './routes/scan.js'

dotenv.config()

// Validate required env vars
const missing: string[] = []
if (!process.env.SAFE_BROWSING_API_KEY) missing.push('SAFE_BROWSING_API_KEY')
if (!process.env.VIRUSTOTAL_API_KEY) missing.push('VIRUSTOTAL_API_KEY')
if (missing.length > 0) {
  console.warn(`Missing env vars (API features disabled): ${missing.join(', ')}`)
}

const app = express()
const PORT = Number(process.env.PORT) || 3001

app.use(cors())
app.use(express.json())

// Rate limiting: 10 scan requests per minute per IP
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again in a minute.' },
})
app.use('/api/scan', scanLimiter)

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' })
})

app.use('/api/scan', scanRoutes)

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})

export default app
