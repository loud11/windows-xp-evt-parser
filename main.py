import dataclasses
import struct
import time
from enum import Flag, auto

# region file handling
fp = open("SysEvent.Evt", "rb")
fp.seek(0)
binContainer = fp.read()
fp.close()
sector_size = 512
encodingFormat = "utf-16le"
# endregion

# region evt header handle definition
FILEHEADERSTRUCTURE = "<IIIIIIIIIIII"
FILEHEADEROFFSET = 0
FILEHEADERSIZE = 48


@dataclasses.dataclass
class evtHeader:
    headerSize: int
    signature: int
    majorVersion: int
    minorVersion: int
    firstRecordOffset: int  # oldest record offset
    eofFileRecordOffset: int
    lastRecordNumber: int  # newest record offset
    firstRecordNumber: int
    maximumFileSize: int
    fileFlags: int
    unknown: int
    copyOfSize: int


class fileFlag(Flag):
    ELF_LOGFILE_HEADER_DIRTY = auto()
    ELF_LOGFILE_HEADER_WRAP = auto()
    ELF_LOGFILE_LOGFULL_WRITTEN = auto()
    ELF_LOGFILE_ARCHIVE_SET = auto()


# endregion
headerInfo = evtHeader(*struct.unpack(FILEHEADERSTRUCTURE, binContainer[FILEHEADEROFFSET:FILEHEADEROFFSET + FILEHEADERSIZE]))
# signature checking
if headerInfo.signature != 0x654c664c:
    print("This is not a evt file")
    exit(-1)
# check evt file flag
print("check evt file flag: ", fileFlag(headerInfo.fileFlags))
print(headerInfo)

# region End of File record definition
EOFRecordStructure = "<IIIIIIIIII"
EOFRecordOffset = headerInfo.eofFileRecordOffset
EOFRecordSize = 40
@dataclasses.dataclass
class EOFStructure:
    EOFRECORDSIZE: int
    signature1: int
    signature2: int
    signature3: int
    signature4: int
    firstRecordOffset: int  # oldest record offset
    EOFRECORDOffset: int
    lastRecordNumber: int  # newest record offset
    firstRecordNumber: int
    copyOfSize: int
# endregion
eofInfo = EOFStructure(*struct.unpack(EOFRecordStructure, binContainer[EOFRecordOffset:EOFRecordOffset + EOFRecordSize]))
print(eofInfo)

#-------------------------------------------------------------------deal with log records
#region event record definition
eventRecordStructure = "<IIIIIIHHHHIIIIII"
eventRecordFirstOffset = headerInfo.firstRecordOffset
eventRecordHeaderSize = 56
@dataclasses.dataclass
class eventRecord:
    recordSize: int
    signature: int
    recordNumber: int
    creationTime: int
    lastWrittenTime: int
    eventIdentifier: int
    eventType: int
    numberOfStrings: int
    eventCategory: int
    unknown: int
    unknown2: int
    eventStringsOffset: int
    userIdSize: int
    userIdendifierOffset: int
    eventDataSize: int
    eventDataOffset: int
class eventTypeDefinition(Flag):
    LOG_ERROR_TYPE = auto()
    LOG_WARNING_TYPE = auto()
    LOG_INFORMATION_TYPE = auto()
    LOG_AUDIT_SUCCESS = auto()
    LOG_AUDIT_FAILURE = auto()
# endregion

eventLogInfo = eventRecord(*struct.unpack(eventRecordStructure, binContainer[eventRecordFirstOffset:eventRecordFirstOffset + eventRecordHeaderSize]))
print(eventLogInfo)
creationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eventLogInfo.creationTime))
lastWrittenTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eventLogInfo.lastWrittenTime))
eventIdentifierInBin = bin(eventLogInfo.eventIdentifier)
eventDataInfo = binContainer[eventRecordFirstOffset:eventRecordFirstOffset+eventLogInfo.eventDataOffset]
print("index",",","binoffset",",","recordNumber",",","creationTime",",","lastWrittenTime",",","eventID",",","eventData")
print(1,",",eventRecordFirstOffset,",",eventLogInfo.recordNumber,",", creationTime,",",lastWrittenTime,",",eventTypeDefinition(eventLogInfo.eventType),",",int(eventIdentifierInBin[-16:],2),",",eventLogInfo.recordNumber,eventDataInfo[eventLogInfo.eventStringsOffset:].decode(encodingFormat))

globalOffset = eventRecordFirstOffset + eventLogInfo.recordSize
index = 2
while(True):
    try:
        eventLogInfo = eventRecord(*struct.unpack(eventRecordStructure, binContainer[globalOffset:globalOffset + eventRecordHeaderSize]))
        creationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eventLogInfo.creationTime))
        lastWrittenTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eventLogInfo.lastWrittenTime))
        eventIdentifierInBin = bin(eventLogInfo.eventIdentifier)
        eventDataInfo = binContainer[globalOffset:globalOffset + eventLogInfo.eventDataOffset]
        print(index,",", globalOffset,",", eventLogInfo.recordNumber,",", creationTime, ",", lastWrittenTime, ",", eventTypeDefinition(eventLogInfo.eventType), ",",int(eventIdentifierInBin[-16:], 2), ",",eventDataInfo[eventLogInfo.eventStringsOffset:].decode(encodingFormat))
        if eofInfo.lastRecordNumber == eventLogInfo.recordNumber:
            print("last log of file", eventLogInfo.recordNumber)
            break
        globalOffset += eventLogInfo.recordSize
        index += 1
    except:
        break

globalOffset = 0x88
while(True):
    try:
        eventLogInfo = eventRecord(*struct.unpack(eventRecordStructure, binContainer[globalOffset:globalOffset + eventRecordHeaderSize]))
        creationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eventLogInfo.creationTime))
        lastWrittenTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eventLogInfo.lastWrittenTime))
        eventIdentifierInBin = bin(eventLogInfo.eventIdentifier)
        eventDataInfo = binContainer[globalOffset:globalOffset + eventLogInfo.eventDataOffset]
        print(index,",", globalOffset,",", eventLogInfo.recordNumber,",", creationTime, ",", lastWrittenTime, ",", eventTypeDefinition(eventLogInfo.eventType), ",",int(eventIdentifierInBin[-16:], 2), ",",eventDataInfo[eventLogInfo.eventStringsOffset:].decode(encodingFormat))
        if eofInfo.lastRecordNumber == eventLogInfo.recordNumber:
            print("last log of file", eventLogInfo.recordNumber)
            break
        globalOffset += eventLogInfo.recordSize
        index += 1
    except:
        break