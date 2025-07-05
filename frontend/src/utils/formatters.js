export const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
};

export const formatPacketSize = (size) => {
    return `${size} bytes`;
};

export const formatProtocol = (protocol) => {
    return protocol.charAt(0).toUpperCase() + protocol.slice(1).toLowerCase();
};