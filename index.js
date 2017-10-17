const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const random = (len = 16) => {
    const digits = '0123456789abcdefghijklmnopqrstuvwxyz';
    let str = '';
    for (let i = 0; i < len; i += 1) {
        const rand = Math.floor(Math.random() * digits.length);
        if (rand !== 0 || str.length > 0) {
            str += digits[rand];
        }
    }
    return str;
};
class ZMXY {
    constructor(option) {
        this.version = '1.0';
        this.url = 'https://zmopenapi.zmxy.com.cn/openapi.do';
        this.charset = 'UTF-8';
        this.platform = 'zmop';
        this.appId = option.appId;
        this.appPrivateKey = option.appPrivateKey;
        this.zmxyPublicKey = option.zmxyPublicKey;
    }
    /**
     * 业务参数转换为字符串
     * @param {Object} params
     * @returns {string}
     */
    paramsToString(params) {
        const sortedParams = Object.keys(params).sort().reduce((r, k) => (r[k] = params[k], r), {});
        return Object.entries(sortedParams).filter(([, value]) => ![null, ''].includes(value)).map(([key, value]) => `${key}=${encodeURIComponent(value)}`).join('&');
    }
    /**
     * 对字符串生成签名
     * @param {String} input
     * @param {String} key
     * @returns {String}
     */
    sign(input, key = this.appPrivateKey) {
        return crypto.createSign('RSA-SHA1').update(input, 'utf8').sign(key, 'base64');
    }
    /**
     * 验证签名
     * @param {String} expected
     * @param {String} sign
     * @param {String} key
     * @returns {Boolean}
     */
    verify(expected, sign, key = this.zmxyPublicKey) {
        return crypto.createVerify('RSA-SHA1').update(expected, 'utf8').verify(key, sign, 'base64');
    }
    /**
     * 公钥加密
     * @param {String} text
     * @param {Number} blockSize
     * @param {String} publicKey
     * @returns {String}
     */
    encrypt(text, blockSize = 128, publicKey = this.zmxyPublicKey) {
        const padding = 11;
        const chunkSize = blockSize - padding;
        const inputBuffer = new Buffer(text);
        const chunksCount = Math.ceil(inputBuffer.length / chunkSize);
        const outputBuffer = new Buffer(chunksCount * blockSize);
        for (let i = 0; i < chunksCount; i += 1) {
            const currentBlock = inputBuffer.slice(chunkSize * i, chunkSize * (i + 1));
            const encryptedChunk = crypto.publicEncrypt({
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            }, currentBlock);
            encryptedChunk.copy(outputBuffer, i * blockSize);
        }
        return outputBuffer.toString('base64');
    }
    /**
     * 私钥解密
     * @param {String} encrypted
     * @param {String} privateKey
     * @returns {String}
     */
    decrypt(encrypted, privateKey = this.appPrivateKey) {
        const chunkSize = 128;
        const decodedBuffer = new Buffer(encrypted, 'base64');
        const chunksCount = Math.ceil(decodedBuffer.length / chunkSize);
        const outputBuffer = new Buffer(chunksCount * chunkSize);
        let totalLength = 0;
        for (let i = 0; i < chunksCount; i += 1) {
            const currentBlock = decodedBuffer.slice(chunkSize * i, Math.min(chunkSize * (i + 1), decodedBuffer.length));
            const decryptedBuf = crypto.privateDecrypt({
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            }, currentBlock);

            decryptedBuf.copy(outputBuffer, totalLength);
            totalLength += decryptedBuf.length;
        }
        return outputBuffer.slice(0, totalLength).toString();
    }
    /**
     * 发起一个API请求
     * @param {String} service
     * @param {Object} params
     * @returns {{params: *, response: *, result: *}}
     */
    async request(service, params) {
        const paramsString = this.paramsToString(params);
        const requestOption = {
            method: 'post',
            url: this.url,
            params: {
                app_id: this.appId,
                charset: this.charset,
                method: service,
                version: this.version,
                platform: this.platform,
                params: this.encrypt(paramsString),
                sign: this.sign(paramsString)
            }
        }
        let response = await axios(requestOption);
        const {
            encrypted,
            biz_response
        } = response.data;

        return encrypted ? JSON.parse(this.decrypt(biz_response)) : JSON.parse(biz_response);
    }
    verifyIvs(params) {
        return this.request('zhima.credit.antifraud.verify', Object.assign({
            product_code: 'w1010100000000002859',
            transaction_id: random(32),
            cert_type: 'IDENTITY_CARD'
        }, params));
    }
}

module.exports = ZMXY;

