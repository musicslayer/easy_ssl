/*
    ASN.1 Encoding Rules
    Generic:
        The first byte of any ASN.1 sequence is the type (Sequence, Integer, etc).
        The second byte is either the size of the value, or the size of its size.
            1. If the second byte is < 0x80 (128) it is considered the size.
            2. If it is > 0x80 it describes the number of bytes of the size.
                ex: 0x82 means the next 2 bytes describe the size of the value.
            3. The special case of exactly 0x80 is "indefinite" length (to end-of-file).
        The rest of the bytes are the value to be encoded.

    UInt:
        Before encoding as a generic value, add "00" prefix to the value if the value's first byte is >= 0x80.

    BitStr:
        Before encoding as a generic value, add a one byte mask prefix to the value indicating how many bits of the value to ignore.
*/

function pack(type, ...hexstrings) {
    // Packs a set of hex strings into one ASN.1 hex string.
    let hex;
    if(type === "02") {
        hex = packUInt(...hexstrings);
    }
    else if(type === "03") {
        hex = packBitStr(...hexstrings);
    }
    else {
        hex = packAny(type, ...hexstrings);
    }
    return hex;
}

function parse(type, bytes) {
    // Parses a single ASN.1 byte value.
    let actualType = bytes.slice(0, 1).toString("hex");
    if(type !== actualType) {
        throw new Error("Unexpected type. Actual: " + actualType + " Expected: " + type);
    }

    let parsedBytes;
    if(type === "02") {
        parsedBytes = parseUInt(bytes);
    }
    else if(type === "03") {
        parsedBytes = parseBitStr(bytes);
    }
    else {
        parsedBytes = parseAny(bytes);
    }
    return parsedBytes;
}

function packGroup(struct) {
    // Packs multiple sets of hex strings into one ASN.1 hex string based on the provided structure.
    let type = struct.type;
    let values = struct.values;

    let hex = "";
    for(let value of values) {
        // Each value is either a string or a child object.
        if(typeof value === "string") {
            hex += value;
        }
        else {
            hex += packGroup(value);
        }
    }
    return pack(type, hex);
}

function parseGroup(bytes, struct) {
    // Parses ASN.1 byte values based on the provided structure.
    let type = struct.type;
    let children = struct.children;

    let parsedBytes = parse(type, bytes);

    let parsedStruct;
    if(children.length === 0) {
        parsedStruct = parsedBytes;
    }
    else {
        parsedStruct = [];
        for(let child of children) {
            let pb = parseGroup(parsedBytes, child);
            let pbc = getBytesConsumed(parsedBytes);
            parsedStruct.push(pb);
            parsedBytes = parsedBytes.slice(pbc);
        }
    }
    return parsedStruct;
}

function packAny(type, ...hexStrings) {
    if(type.length !== 2) {
        throw new Error("Invalid type: " + type);
    }

    let str = combineHexStrings(...hexStrings);

    // Begin with the type byte.
    let hex = type;

    // If the value is large, we need to append the number of size bytes first.
    let byteLength = str.length / 2;
    if(byteLength >= 0x80) {
        let numBinaryDigits = byteLength.toString(2).length;
        numSizeBytes = 1 + Math.floor(numBinaryDigits / 9);
        hex += numToHex(0x80 + numSizeBytes);
    }

    // Append size bytes.
    hex += numToHex(byteLength);

    // Append value.
    hex += str;

    return hex;
}

function parseAny(bytes) {
    let numSizeBytes = getNumSizeBytes(bytes);
    let bytesConsumed = getBytesConsumed(bytes);

    // The type byte and size bytes are consumed, but not included in the value.
    let parsedBytes = bytes.slice(1 + numSizeBytes, bytesConsumed);
    
    return parsedBytes;
};

function packUInt(...hexStrings) {
    // Add the UInt prefix if the first byte is large.
    let first = parseInt(hexStrings[0].slice(0, 2), 16);
    if(first >= 0x80) {
        hexStrings.unshift("00");
    }

    return packAny("02", ...hexStrings);
};

function parseUInt(bytes) {
    let parsedBytes = parseAny(bytes);

    // If the first byte is 0 and there are more bytes afterwards, then the first byte is the prefix and not part of the value.
    if(parsedBytes[0] === 0 && parsedBytes.byteLength > 1) {
        parsedBytes = parsedBytes.slice(1);
    }

    return parsedBytes;
};

function packBitStr(...hexStrings) {
    // Always add "00" so none of the value is ignored.
    hexStrings.unshift("00");
    return packAny("03", ...hexStrings);
};

function parseBitStr(bytes) {
    let parsedBytes = parseAny(bytes);

    if(parsedBytes[0] !== 0) {
        throw new Error("Error: Cannot parse a BitStr with a nonzero mask byte.");
    }

    // BitStr values always have one mask byte.
    parsedBytes = parsedBytes.slice(1);
    return parsedBytes;
};

function getNumSizeBytes(bytes) {
    let numSizeBytes = 1;

    // Check the second byte to see if there are more size bytes.
    if(bytes[1] > 0x80) {
        numSizeBytes += bytes[1] - 0x80;
    }
    else if(bytes[1] == 0x80){
        throw new Error("Error: Cannot parse a value with a size byte of 0x80.");
    }

    return numSizeBytes;
}

function getBytesConsumed(bytes) {
    // The type byte, size bytes, and value bytes all consumed.
    let numSizeBytes = getNumSizeBytes(bytes);

    let size;
    if(numSizeBytes === 1) {
        size = bytes[1];
    }
    else {
        let sizeArray = bytes.slice(2, 1 + numSizeBytes);
        size = parseInt(sizeArray.toString("hex"), 16);
    }

    return 1 + numSizeBytes + size;
}

function combineHexStrings(...hexStrings) {
    for(let hexString of hexStrings) {
        if(hexString.length % 2 !== 0) {
            throw new Error("Hex string \"" + hexString + "\" must have an even length.");
        }
    }

    return hexStrings
        .join("")
        .replace(/\s+/g, "")
        .toLowerCase();
}

function numToHex(d) {
    d = d.toString(16);

    // All hex strings must have an even number of digits.
    if(d.length % 2 !== 0) {
        return "0" + d;
    }
    return d;
};

module.exports.pack = pack;
module.exports.parse = parse;
module.exports.packGroup = packGroup;
module.exports.parseGroup = parseGroup;