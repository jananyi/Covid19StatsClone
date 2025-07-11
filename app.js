const express = require('express')
const app = express()
app.use(express.json())

const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const dbPath = path.join(__dirname, 'covid19IndiaPortal.db')
let db = null

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Server running at http://localhost:3000/')
    })
  } catch (e) {
    console.log(`DB Error: ${e.message}`)
    process.exit(1)
  }
}

initializeDbAndServer()

// JWT Authentication Middleware
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization']
  let jwtToken

  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }

  if (jwtToken === undefined) {
    response.status(401)
    response.send('Invalid JWT Token')
  } else {
    jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
      if (error) {
        response.status(401)
        response.send('Invalid JWT Token')
      } else {
        request.username = payload.username
        next()
      }
    })
  }
}

// API 1: Login
app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const getUserQuery = `SELECT * FROM user WHERE username = ?`
  const user = await db.get(getUserQuery, [username])

  if (!user) {
    response.status(400)
    response.send('Invalid user')
  } else {
    const isPasswordValid = await bcrypt.compare(password, user.password)
    if (!isPasswordValid) {
      response.status(400)
      response.send('Invalid password')
    } else {
      const payload = {username: username}
      const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
      response.send({jwtToken})
    }
  }
})

// API 2: Get all states
app.get('/states/', authenticateToken, async (request, response) => {
  const getStatesQuery = `SELECT * FROM state;`
  const states = await db.all(getStatesQuery)
  response.send(
    states.map(state => ({
      stateId: state.state_id,
      stateName: state.state_name,
      population: state.population,
    })),
  )
})

// API 3: Get state by ID
app.get('/states/:stateId/', authenticateToken, async (request, response) => {
  const {stateId} = request.params
  const getStateQuery = `SELECT * FROM state WHERE state_id = ?`
  const state = await db.get(getStateQuery, [stateId])
  response.send({
    stateId: state.state_id,
    stateName: state.state_name,
    population: state.population,
  })
})

// API 4: Create a district
app.post('/districts/', authenticateToken, async (request, response) => {
  const {districtName, stateId, cases, cured, active, deaths} = request.body
  const insertDistrictQuery = `
    INSERT INTO district (district_name, state_id, cases, cured, active, deaths)
    VALUES (?, ?, ?, ?, ?, ?);`
  await db.run(insertDistrictQuery, [
    districtName,
    stateId,
    cases,
    cured,
    active,
    deaths,
  ])
  response.send('District Successfully Added')
})

// API 5: Get district by ID
app.get(
  '/districts/:districtId/',
  authenticateToken,
  async (request, response) => {
    const {districtId} = request.params
    const getDistrictQuery = `SELECT * FROM district WHERE district_id = ?`
    const district = await db.get(getDistrictQuery, [districtId])
    response.send({
      districtId: district.district_id,
      districtName: district.district_name,
      stateId: district.state_id,
      cases: district.cases,
      cured: district.cured,
      active: district.active,
      deaths: district.deaths,
    })
  },
)

// API 6: Delete district
app.delete(
  '/districts/:districtId/',
  authenticateToken,
  async (request, response) => {
    const {districtId} = request.params
    const deleteQuery = `DELETE FROM district WHERE district_id = ?`
    await db.run(deleteQuery, [districtId])
    response.send('District Removed')
  },
)

// API 7: Update district
app.put(
  '/districts/:districtId/',
  authenticateToken,
  async (request, response) => {
    const {districtId} = request.params
    const {districtName, stateId, cases, cured, active, deaths} = request.body
    const updateQuery = `
    UPDATE district
    SET district_name = ?, state_id = ?, cases = ?, cured = ?, active = ?, deaths = ?
    WHERE district_id = ?;`
    await db.run(updateQuery, [
      districtName,
      stateId,
      cases,
      cured,
      active,
      deaths,
      districtId,
    ])
    response.send('District Details Updated')
  },
)

// API 8: Get stats for a state
app.get(
  '/states/:stateId/stats/',
  authenticateToken,
  async (request, response) => {
    const {stateId} = request.params
    const statsQuery = `
    SELECT
      SUM(cases) AS totalCases,
      SUM(cured) AS totalCured,
      SUM(active) AS totalActive,
      SUM(deaths) AS totalDeaths
    FROM district
    WHERE state_id = ?;`
    const stats = await db.get(statsQuery, [stateId])
    response.send(stats)
  },
)

// API 9: Get state name for district
app.get(
  '/districts/:districtId/details/',
  authenticateToken,
  async (request, response) => {
    const {districtId} = request.params
    const query = `
    SELECT state.state_name AS stateName
    FROM district
    JOIN state ON district.state_id = state.state_id
    WHERE district.district_id = ?;`
    const result = await db.get(query, [districtId])
    response.send(result)
  },
)

module.exports = app
