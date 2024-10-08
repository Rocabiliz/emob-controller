/*
 * Copyright (C) 2007-2015 Siemens AG
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*******************************************************************
 *
 * @author Daniel.Peintner.EXT@siemens.com
 * @version 0.9.3 
 * @contact Joerg.Heuer@siemens.com
 *
 * <p>Code generated by EXIdizer</p>
 * <p>Schema: V2G_CI_MsgDef.xsd</p>
 *
 *
 ********************************************************************/



/**
 * \file 	EXIOptions.h
 * \brief 	EXI Options for the EXI Codec
 *
 */

#ifndef EXI_OPTIONS_H
#define EXI_OPTIONS_H

#ifdef __cplusplus
extern "C" {
#endif


/** EXI alignment - Option bit-packed */
#define BIT_PACKED 1
/** EXI alignment - Option byte-packed */
#define BYTE_ALIGNMENT  2
/** EXI alignment */
/**
 * \brief 		EXI Option 'alignment'
 *
 *				The alignment option is used to control the alignment of event codes and content items.
 *				Default Value: bit-packed
 */
#define EXI_OPTION_ALIGNMENT BIT_PACKED



/**
 * \brief 		EXI Option 'strict'
 *
 *				Strict interpretation of schemas is used to achieve better compactness.
 *				Default Value: false
 */
#define EXI_OPTION_STRICT 0


/**
 * \brief 		EXI Option 'valueMaxLength'
 *
 *				Specifies the maximum string length of value content items to be
 *				considered for addition to the string table.
 *				Default Value: unbounded (-1)
 */
#define EXI_OPTION_VALUE_MAX_LENGTH -1


/**
 * \brief 		EXI Option 'valuePartitionCapacity'
 *
 *				Specifies the total capacity of value partitions in a string table.
 *				Default Value: unbounded (-1)
 */
#define EXI_OPTION_VALUE_PARTITION_CAPACITY 0


#ifdef __cplusplus
}
#endif

#endif /* EXI_OPTIONS_H */
