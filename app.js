const express = require('express')
const db = require('./db')
const randomstring = require('randomstring')

const app = express()

app.set('view engine', 'ejs')

app.get('/', (req, res) => {
    res.send('Welcome to OAuth 2.0 server')
})

app.get('/authorize', (req, res) =>{

    //Client ID validation
    const clientID = req.query.client_id
    if(!clientID){
        return res.status(400).render('error', {message: 'Missing required parameter: client_id'})
    }


    const client = db.getClientByID(clientID)
    if(!client){
        return res.status(400).render('error', {message: 'Invalid client_id'})
    }

    //Response type validation
    const responseType = req.query.response_type
    if(!responseType){
        return res.status(400).render('error', {message: 'Missing required parameter: response_type'})
    }
    
    const supportedResTypes = ['code']

    if(!supportedResTypes.includes(responseType)){
        return res.status(400).render('error', {message: 'Invalid response_type'})  
    }

    //redirect uri validation
    const validUris = client.redirect_uris
    if(!validUris || !validUris.length){
        return res.status(400).render('error', {message: 'No redirect URIs configured for the client'})
    }

    let redirectUri = req.query.redirect_uri || null
    if(redirectUri && !validUris.includes(redirectUri)){
        return res.status(400).render('error', {message: 'Invalid redirect_uri: ' + redirectUri})
    }

    if(!redirectUri){
        redirectUri = validUris[0]
    }

    //Check session
    // If no session, redirect to /login


    //Create authz code
    const code = randomstring.generate({length: 32, charset: 'alphanumeric'})
    const expiresAt = moment().add(10, 'minutes').valueOf()
    const context = {
        code,
        expiresAt,
        clientID,
        redirectUri, 
        user_id: '1'
    }

    //Save code in db
    db.saveCodeContext(context)

    const url = new URL(redirectUri)

    res.status(501).render('error', {message: '/authorize is not implemented yet'})
})

const PORT = 8500
app.listen(PORT, () => console.log('Listening on port ${PORT}'))