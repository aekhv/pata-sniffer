#ifndef ATAREGISTERS_H
#define ATAREGISTERS_H

#define CS0_ASSERTED				(0x02 << 3)
#define CS0_NOT_ASSERTED			(0x03 << 3)
#define CS1_ASSERTED				(0x01 << 3)
#define CS1_NOT_ASSERTED			(0x03 << 3)

#define ATA_REG_ALT_STATUS			0x06 | (CS0_NOT_ASSERTED & CS1_ASSERTED)
#define ATA_REG_STATUS				0x07 | (CS0_ASSERTED & CS1_NOT_ASSERTED)
#define ATA_REG_ERROR				0x01 | (CS0_ASSERTED & CS1_NOT_ASSERTED)

#define ATA_REG_DEVICE_CONTROL		0x06 | (CS0_NOT_ASSERTED & CS1_ASSERTED)
#define ATA_REG_COMMAND				0x07 | (CS0_ASSERTED & CS1_NOT_ASSERTED)
#define ATA_REG_FEATURES			0x01 | (CS0_ASSERTED & CS1_NOT_ASSERTED)

#define ATA_REG_DATA				0x00 | (CS0_ASSERTED & CS1_NOT_ASSERTED)

#define ATA_REG_SECTOR_COUNT		0x02 | (CS0_ASSERTED & CS1_NOT_ASSERTED)

#define ATA_REG_CHS_SECTOR_NUMBER	0x03 | (CS0_ASSERTED & CS1_NOT_ASSERTED)
#define ATA_REG_CHS_CYLINDER_LOW	0x04 | (CS0_ASSERTED & CS1_NOT_ASSERTED)
#define ATA_REG_CHS_CYLINDER_HIGH	0x05 | (CS0_ASSERTED & CS1_NOT_ASSERTED)
#define ATA_REG_CHS_DEVICE_HEAD		0x06 | (CS0_ASSERTED & CS1_NOT_ASSERTED)

#define ATA_REG_LBA_LOW				ATA_REG_CHS_SECTOR_NUMBER
#define ATA_REG_LBA_MID				ATA_REG_CHS_CYLINDER_LOW
#define ATA_REG_LBA_HIGH			ATA_REG_CHS_CYLINDER_HIGH
#define ATA_REG_LBA_DEVICE			ATA_REG_CHS_DEVICE_HEAD

#endif // ATAREGISTERS_H
