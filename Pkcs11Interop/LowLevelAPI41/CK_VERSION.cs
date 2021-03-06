﻿/*
 *  Pkcs11Interop - Managed .NET wrapper for unmanaged PKCS#11 libraries
 *  Copyright (c) 2012-2015 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs11Interop is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs11Interop is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
 */

using System.Runtime.InteropServices;

namespace Net.Pkcs11Interop.LowLevelAPI41
{
    /// <summary>
    /// Describes the version
    /// </summary>
#if SILVERLIGHT
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public class CK_VERSION
#else
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_VERSION
#endif
    {
        /// <summary>
        /// Major version number (the integer portion of the version)
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Major;
        
        /// <summary>
        /// Minor version number (the hundredths portion of the version)
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Minor;

        /// <summary>
        /// Returns a string that represents the current CK_VERSION structure.
        /// </summary>
        /// <returns>String that represents the current CK_VERSION structure.</returns>
        public override string ToString()
        {
            return string.Format("{0}.{1}", Major[0], Minor[0]);
        }
    }
}
