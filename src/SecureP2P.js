const DagCbor = require('ipld-dag-cbor')
const protons = require('protons')
const crypto = require('asymmetric-crypto')
const NodeCrypto = require('crypto')
const EventEmitter = require('events');

const ProtobufFormat = `
    message Packing {
        required int32 type = 1;
        required bytes payload = 2;
        optional string protocol = 3;
        optional int32 code = 4;
    }
`
const ProtobufSerializer = protons(ProtobufFormat)

const MESSAGE_TYPES = {
    ASK_JOIN: 1, //Ask to upgrade.
    PUSH_JOIN: 2, //Respond to connection upgrade
    NodeInfo: 3,
    QUERY_Application: 4,
    PUSH_Application: 5,
    Ping: 6,
    Pong: 7,
    EncryptedMessage: 8
}

class ProtocolBaseHandler {
    constructor(name, version) {
        this.name = name;
        //Version is a string with the format /MAJOR/MINOR/PATCH, or /MAJOR.MINOR.PATCH
        this.version = version;
        //Final protocol name would look like /MyProtcol/2/5/25

        this.handlers = {};
    }
}

class SecureP2P {
    constructor(pubsub, options = {}) {
        this.pubsub = pubsub
        if (!options.identity) {
            throw "Identity is a required option"
        }
        if (!options.BroadcastTimeout) {
            options.BroadcastTimeout = 60000; //60 seconds in ms
        }
        if (!options.PingTimeout) {
            options.PingTimeout = 120000; //120 seconds in ms
        }
        this.options = options;
        this.channels = {};
        this.broadcastChannels = ["testChannel"];
        this.NeighborPeerInfo = {};
        this.directConnections = {};
        this.requestHandlers = {};
        
        
        this.events = new EventEmitter()
        this._broadcast = this._broadcast.bind(this)
        this._handleMessage = this._handleMessage.bind(this)
        this._handleReceive = this._handleReceive.bind(this)
        this.pingAll = this.pingAll.bind(this)
    }
    async start() {
        this.keyPair = crypto.keyPair(); //TODO: use seed for encryption/decryption
        for(var pubsubID of this.broadcastChannels) {
            this.pubsub.subscribe(pubsubID, this._handleReceive, () => {})
        }
        this._broadcast()
        setInterval(this._broadcast, this.options.BroadcastTimeout)
        setInterval(this.pingAll, this.options.PingTimeout)
    }
    /**
     * 
     * @param {*} PubsubID Pubsub Negotiation ID/broadcast channel;
     * @param {*} PeerID 
     * @param {Object} options Connection options
     */
    async connectTo(PubsubID, PeerID, options = {}) {
        if(!options.enc) {
            options.enc = false; //Default no encryption
        }
        return new Promise((resolve, reject) => {
            let conjoinedChannelID = PeerID + this.pubsub._id; //Concat for now. Use hashing/better determinism system later.
            let reqid = NodeCrypto.randomBytes(20).toString("base64");
            var message = {
                type: MESSAGE_TYPES.ASK_JOIN,
                payload: {
                    to: PeerID,
                    chanid: conjoinedChannelID,
                    config: {
                        enc: options.enc
                    },
                    reqid 
                }
            }
            this.requestHandlers[reqid] = {
                origin: PeerID
            }
            this.pubsub.publish(PubsubID, message);
            this.events.once(`join.${reqid}`, (payload) => {
                if(payload.code === 1) {
                    //Trigger success!
                    this.directConnections[PeerID] = {
                        chanid: conjoinedChannelID,
                        enc: options.enc
                    };
                    this.pubsub.subscribe(conjoinedChannelID, this._handleReceive, () => {})
                    this.ping(PeerID)
                }
                resolve();
            })
        })
    }
    ping(PeerID) {
        if(!this.directConnections[PeerID]) {
            return; //No direct connection is present.
        }
        this.pubsub.publish(this.directConnections[PeerID].chanid, this._directPacking({
            type: MESSAGE_TYPES.Ping,
            payload: {
                timestamp: new Date() / 1
            }
        },PeerID))
    }
    pingAll() {
        for(var PeerID in this.directConnections) {
            this.ping(PeerID)
        }
    }
    _broadcast() {
        for (var pubsubID of this.broadcastChannels) {
            var message = {
                type: MESSAGE_TYPES.NodeInfo,
                payload: {
                    nodeInfo: {
                        pek: this.keyPair.publicKey //public encryption key
                    }
                }
            }
            this.pubsub.publish(pubsubID, message)
        }
    }
    publish(PubsubID, message) {

    }
    /**
     * Transition to using this.publish
     * @param {*} message 
     * @param {*} PeerId 
     */
    _directPacking(message, PeerId) {
        var connectionInfo = this.directConnections[PeerId];

        if(connectionInfo.enc === true) {
            return {
                type: MESSAGE_TYPES.EncryptedMessage,
                payload:this._encrypt(message, PeerId) 
            }
        } else {
            return message;
        }
    }
    /**
     * Transition to using this.subscribe automatically decrypt incoming
     * @param {*} message 
     * @param {*} PeerId 
     */
    _directUnpacking(message, PeerId) {
        var connectionInfo = this.directConnections[PeerId];
        if(connectionInfo.enc === true) {
            return this._decrypt(message, PeerId)
        } else {
            return message;
        }
    }
    /**
     * Serialization of payload
     * @param {Object} data 
     */
    _serialize(data) {
        return DagCbor.util.serialize(data)
    }
    /**
     * Deserialization of payload
     * @param {Buffer} data 
     */
    _deserialize(data) {
        return DagCbor.util.deserialize(data)
    }
    _encrypt(plaintext, destPeerId) {
        var NodeInfo = this.NeighborPeerInfo[destPeerId];
        
        return crypto.encrypt(DagCbor.util.serialize(plaintext).toString("base64"), NodeInfo.pek, this.keyPair.secretKey)
    }
    _decrypt(ciphertext, receivePeerId) {
        var NodeInfo = this.NeighborPeerInfo[receivePeerId];
        var buf = Buffer.from(crypto.decrypt(ciphertext.data, ciphertext.nonce,
            NodeInfo.pek, this.keyPair.secretKey), "base64")
        return DagCbor.util.deserialize(buf);
    }
    _handleReceive(pubsubID, message, fromID) {
        if (typeof message === "string") {
            message = JSON.parse(message)
        } else if (Buffer.isBuffer(message)) {
            ProtobufSerializer.Packing.decode(message)
            message = DagCbor.util.deserialize(message)
        }
        if (!message.type) {
            return;
        }
        if (message.type === MESSAGE_TYPES.EncryptedMessage) {
            //Do decryption here
            this._handleMessage(pubsubID, this._decrypt(message.payload, fromID), fromID)
        } else {
            this._handleMessage(pubsubID, message, fromID)
        }
    }
    _handleMessage(pubsubID, message, fromID) {
        switch (message.type) {
            case MESSAGE_TYPES.ASK_JOIN: {
                if(message.payload.to !== this.pubsub._id) {
                    return;
                }
                if(this.directConnections[fromID]) {
                    return;
                }

                this.pubsub.publish(pubsubID, {
                    type: MESSAGE_TYPES.PUSH_JOIN,
                    payload: {
                        to: fromID,
                        reqid: message.payload.reqid,
                        code: 1 //Success
                    }
                })
                this.directConnections[fromID] = {
                    chanid: message.payload.chanid,
                    enc: message.payload.config.enc
                }
                this.pubsub.subscribe(message.payload.chanid, this._handleReceive, () => {})

                break;
            }
            case MESSAGE_TYPES.PUSH_JOIN: {
                if(!this.requestHandlers[message.payload.reqid]) {
                    return;
                }
                const requestInfo = this.requestHandlers[message.payload.reqid];
                if(requestInfo.origin !== fromID) {
                    return;
                }
                this.events.emit(`join.${message.payload.reqid}`, message.payload)
                this.pubsub.subscribe(message.payload.chanid, this._handleReceive, () => {})
                delete this.requestHandlers[message.payload.reqid];
                break;
            }
            case MESSAGE_TYPES.NodeInfo: {
                this.NeighborPeerInfo[fromID] = message.payload.nodeInfo;
                if(!this.directConnections[fromID]) {
                    this.connectTo(pubsubID, fromID)
                }
                break;
            }
            case MESSAGE_TYPES.Ping: {
                this.pubsub.publish(pubsubID, this._directPacking({
                    type: MESSAGE_TYPES.Pong,
                    payload: {
                        timestamp: new Date() / 1
                    }
                }, fromID))
                break;
            }
            case MESSAGE_TYPES.Pong: {
                //Handle pong. Record latency.
                break;
            }
            case MESSAGE_TYPES.QUERY_Application: {
                break;
            }
            case MESSAGE_TYPES.PUSH_Application: {
                break;
            }
            default: {
                //Do nothing. Not supported to ever happened.
            }
        }
    }
    async registerProtocol(id, name, version) {

    }
    /**
     * 
     * @param {String} id Orbitdb ID of store 
     * @param {*} method 
     * @param {*} handler 
     */
    async registerHandler(id, method, handler) {

    }
}
module.exports = SecureP2P;