const makeApiResponse = (message, type, status_code, data) => {
    let response = {
        message: message,
        type: type,
        code: status_code,
        data: data ? data : [] 
    }
    return response;
};

module.exports = makeApiResponse;