const CLIENTS = [
    { id: '1', secret: 'secret1', redirect_uris: ['https://thameera.com/callback']}
]

const AUTHZ_CODES = []

const getClientByID = id => {
    return CLIENTS.find(c => c.id === id)
}

const saveCodeContext = ctx => {
    AUTHZ_CODES.push(ctx)
}

module.exports = {
    getClientByID,
    saveCodeContext
}