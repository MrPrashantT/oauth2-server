const express = require('express')

const app = express()

app.set('view engine', 'ejs')

app.get('/', (req, res) => {
    res.send('Welcome to OAuth 2.0 server')
})

app.get('/authorize', (req, res) =>{
    res.status(501).render('error', {message: '/authorize is not implemented yet'})
})

const PORT = 8500
app.listen(PORT, () => console.log('Listening on port ${PORT}'))