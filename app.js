const express = require('express')
const db = require('./db')
const moment = require('moment')
const randomstring = require('randomstring')

const app = express()
app.use(express.urlencoded({extended: true}))
app.use(express.json())

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
        redirectUri: req.query.redirect_uri, 
        user_id: '1'
    }

    //Save code in db
    db.saveCodeContext(context)

    const url = new URL(redirectUri)
    url.searchParams.set('code', code)

    res.redirect(url)
})

app.post('/token', (req, res) =>{
    const body = req.body || {}
    const grant = body.grant_type
    if(!grant){
        return res.status(400).json({error: 'invalid_request', error_description: 'Grant type not specified'});
    }

    const supportedGrantTypes = ['authorization_code']

    if(!supportedGrantTypes.includes(grant)){
        return res.status(400).json({error: 'unsupported_grant_type', error_description: 'Grant type not supported'});
    }

    const auth = req.headers['authorization']

    let client = null

    if(auth){
        //basic auth
        const parts = auth.trim().split(' ')
        if(parts.length !== 2 || parts[0].toLowerCase() !== 'basic'){
            res.set('WWW-Authenticate', 'Basic')
            return res.status(401).json({error: 'invalid_client', error_description: 'Unsupported authentication method'})
        }

        const creds = Buffer.from(parts[1], 'base64').toString('ascii').split(':')
        client = db.getClientByID(creds[0])

        if(!client || client.secret !== creds[1]){
            res.set('WWW-Authenticate', 'Basic')
            return res.status(401).json({error: 'invalid_client', error_description: 'Invalid client ID or secret'})
        }
    } else {
        //json body auth
        if(!body.client_id || !body.client_secret){
            return res.status(400).json({error: 'invalid_client', error_description: 'Client auth failed'})
        }

        client = db.getClientByID(body.client_id)
        if(!client || client.secret !== body.client_secret){
            return res.status(401).json({error: 'invalid_client', error_description: 'Invalid client or secret'})
        }
    }

    if(!body.code){
        return res.status(400).json({error:'invalid_request', error_description: 'Missing required parameter: code'})
    }

    const ctx = db.getCodeContext(body.code)

    if(!ctx){
        return res.status(400).json({error:'invalid_grant', error_description: 'Invalid authorization code'})
    }

    db.deleteCodeContext(body.code)

    if(moment().isAfter(ctx.expiresAt)){
        return res.status(400).json({error:'invalid_grant', error_description: 'Expired authorization code'})
    }

    if(ctx.clientID !== client.id){
        return res.status(400).json({error:'invalid_grant', error_description: 'Invalid authorization code'})
    }

    if(ctx.redirectUri){
        if(body.redirect_uri !== ctx.redirect_uri){
            return res.status(400).json({error:'invalid_grant', error_description: 'Invalid redirect uri'})
        }
    }

    const token = 'at-' + randomstring.generate({length: 32, charset: 'alphanumeric'})
    const tokenCtx = {
        token,
        expiresAt: moment().add(120, 'minutes').valueOf(),
        clientID: ctx.clientID,
        user_id: ctx.user_id
    }

    db.saveAccessToken(tokenCtx)


    res.set('Cache-Control', 'no-store')
    res.set('Pragma', 'no-cache')
    res.status(200).json({
        access_token: token,
        token_type: 'Bearer',
        expires_in: 120 * 60
    })
})

const PORT = 8500
app.listen(PORT, () => console.log('Listening on port ${PORT}'))