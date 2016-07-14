var bcrypto = require('./crypto')
var bufferutils = require('./bufferutils')
var bufferReverse = require('buffer-reverse')
var inherits = require('inherits')
var Transaction = require('./transaction')
var typeforce = require('typeforce')
var types = require('./types')

function WitnessTransaction () {
  Transaction.call(this)

  this.witnesses = []
}

inherits(WitnessTransaction, Transaction)

WitnessTransaction.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt8 () {
    var i = buffer.readUInt8LE(offset)
    offset += 1
    return i
  }

  function readUInt32 () {
    var i = buffer.readUInt32LE(offset)
    offset += 4
    return i
  }

  function readUInt64 () {
    var i = bufferutils.readUInt64LE(buffer, offset)
    offset += 8
    return i
  }

  function readVarInt () {
    var vi = bufferutils.readVarInt(buffer, offset)
    offset += vi.size
    return vi.number
  }

  function readScript () {
    return readSlice(readVarInt())
  }

  var tx = new WitnessTransaction()
  tx.version = readUInt32()

  if (readUInt8() !== 0x00) throw new TypeError('Unsupported witness marker')
  if (readUInt8() !== 0x01) throw new TypeError('Unsupported witness flag')

  var vinLen = readVarInt()
  for (var i = 0; i < vinLen; ++i) {
    tx.ins.push({
      hash: readSlice(32),
      index: readUInt32(),
      script: readScript(),
      sequence: readUInt32()
    })
  }

  var voutLen = readVarInt()
  for (i = 0; i < voutLen; ++i) {
    tx.outs.push({
      value: readUInt64(),
      script: readScript()
    })
  }

  var witnessesLen = readVarInt()
  for (i = 0; i < witnessesLen; ++i) {
    tx.witnesses.push(readScript)
  }

  tx.locktime = readUInt32()

  if (__noStrict) return tx
  if (offset !== buffer.length) throw new Error('Transaction has unexpected data')

  return tx
}

var EMPTY_SCRIPT = new Buffer(0)

WitnessTransaction.prototype.addInput = function (hash, index, sequence, witness) {
  typeforce(types.tuple(
    types.Hash256bit,
    types.UInt32,
    types.maybe(types.UInt32),
    types.maybe(types.Buffer)
  ), arguments)

  if (types.Null(sequence)) {
    sequence = Transaction.DEFAULT_SEQUENCE
  }

  // Add the input and return the input's index
  var vin = (this.ins.push({
    hash: hash,
    index: index,
    script: EMPTY_SCRIPT,
    sequence: sequence
  }) - 1)

  this.witnesses[vin] = witness
  return vin
}

WitnessTransaction.prototype.byteLength = function () {
  function scriptSize (someScript) {
    var length = someScript.length

    return bufferutils.varIntSize(length) + length
  }

  return (
    8 +
    bufferutils.varIntSize(this.ins.length) +
    bufferutils.varIntSize(this.outs.length) +
    bufferutils.varIntSize(this.witnesses.length) +
    this.ins.reduce(function (sum, input) { return sum + 40 + scriptSize(input.script) }, 0) +
    this.outs.reduce(function (sum, output) { return sum + 8 + scriptSize(output.script) }, 0) +
    this.witnesses.reduce(function (sum, witness) { return sum + scriptSize(witness) }, 0)
  )
}

WitnessTransaction.prototype.getWitnessHash = function () {
  return bcrypto.hash256(this.toWitnessBuffer())
}

WitnessTransaction.prototype.getWitnessId = function () {
  // transaction hash's are displayed in reverse order
  return bufferReverse(this.getWitnessHash()).toString('hex')
}

WitnessTransaction.prototype.setInputScript = function () {
  throw new TypeError('setInputScript not supported for Witness Transactions')
}

WitnessTransaction.prototype.setWitness = function (index, witness) {
  typeforce(types.tuple(types.Number, types.Buffer), arguments)

  this.witnesses[index] = witness
}

WitnessTransaction.prototype.toBuffer = function () {
  var buffer = new Buffer(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  function writeUInt8 (i) {
    buffer.writeUInt8(i, offset)
    offset += 4
  }

  function writeUInt32 (i) {
    buffer.writeUInt32LE(i, offset)
    offset += 4
  }

  function writeUInt64 (i) {
    bufferutils.writeUInt64LE(buffer, i, offset)
    offset += 8
  }

  function writeVarInt (i) {
    var n = bufferutils.writeVarInt(buffer, i, offset)
    offset += n
  }

  writeUInt32(this.version)
  writeUInt8(0x00) // marker
  writeUInt8(0x01) // flag
  writeVarInt(this.ins.length)

  this.ins.forEach(function (txIn) {
    writeSlice(txIn.hash)
    writeUInt32(txIn.index)
    writeVarInt(txIn.script.length)
    writeSlice(txIn.script)
    writeUInt32(txIn.sequence)
  })

  writeVarInt(this.outs.length)
  this.outs.forEach(function (txOut) {
    if (!txOut.valueBuffer) {
      writeUInt64(txOut.value)
    } else {
      writeSlice(txOut.valueBuffer)
    }

    writeVarInt(txOut.script.length)
    writeSlice(txOut.script)
  })

  writeVarInt(this.witnesses.length)
  this.witnesses.forEach(function (witness) {
    writeVarInt(witness.length)
    writeSlice(witness)
  })

  writeUInt32(this.locktime)

  return buffer
}

module.exports = WitnessTransaction
