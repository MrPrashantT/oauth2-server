const CLIENTS = [
    { id: '1', secret: 'secret1', redirect_uris: ['https://thameera.com/callback']}
]

let AUTHZ_CODES = []

const ACCESS_TOKENS = []

const getClientByID = id => {
    return CLIENTS.find(c => c.id === id)
}

const saveCodeContext = ctx => {
    AUTHZ_CODES.push(ctx)
}

const getCodeContext = code => {
    return AUTHZ_CODES.find(ctx => ctx.code == code)
}

const deleteCodeContext = code => {
    AUTHZ_CODES = AUTHZ_CODES.filter(ctx => ctx.code !== code)
}

const saveAccessToken = ctx => {
    ACCESS_TOKENS.push(ctx)
}

module.exports = {
    getClientByID,
    saveCodeContext,
    getCodeContext,
    deleteCodeContext,
    saveAccessToken
}