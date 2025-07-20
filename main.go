///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - main.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/pflag"
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/ssh"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const (
	// TELNET Commands.
	TelcmdNOP  = 241 // No operation
	TelcmdAYT  = 246 // Are You There?
	TelcmdSB   = 250 // Subnegotiation Begin
	TelcmdSE   = 240 // Subnegotiation End
	TelcmdIAC  = 255 // Interpret As Command
	TelcmdDONT = 254 // DONT
	TelcmdDO   = 253 // DO
	TelcmdWONT = 252 // WONT
	TelcmdWILL = 251 // WILL

	// TELNET Command Options.
	TeloptBinary          = 0
	TeloptEcho            = 1
	TeloptSuppressGoAhead = 3
	TeloptSGA             = 3   // Suppress Go Ahead
	TeloptStatus          = 5   // Status
	TeloptTimingMark      = 6   // Timing Mark
	TeloptNAWS            = 31  // Negotiate About Window Size
	TeloptTS              = 32  // Terminal Speed
	TeloptRM              = 33  // Remote Flow Control
	TeloptNewEnviron      = 39  // New Environment Option
	TeloptTTYPE           = 24  // Terminal Type
	TeloptXDisplay        = 35  // X Display Location
	TeloptOldEnviron      = 36  // Old Environment Option
	TeloptAuth            = 37  // Authentication Option
	TeloptEncrypt         = 38  // Encryption Option
	TeloptCompPort        = 40  // Com Port Control
	TeloptMSSP            = 70  // Mud Server Status Protocol
	TeloptMCCP2           = 86  // Mud Client Compression Protocol 2
	TeloptMCCP3           = 87  // Mud Client Compression Protocol 3
	TeloptMSP             = 90  // Mud Sound Protocol
	TeloptMXP             = 91  // Mud Extension Protocol
	TeloptATCP            = 200 // Achaea Telnet Client Protocol
	TeloptGMCP            = 201 // Generic Mud Client Protocol
	TeloptLineMode        = 34  // Line Mode
	TeloptLinemode        = 34  // Line Mode (duplicate, common typo)
	TeloptNewEnvironOpt   = 39  // New Environment Option (duplicate)
	TeloptEnd             = 255 // End of option list

	// TELNET subnegotiation commands.
	TelnetIs   = 0
	TelnetSend = 1

	// TELNET Line Mode subnegotiation commands.
	TeloptLMODE_MODE        = 1
	TeloptLMODE_FORWARDMASK = 2
	TeloptLMODE_SLC         = 3
	TeloptLMODE_ACK         = 4
	TeloptLMODE_EOF         = 5
	TeloptLMODE_SYNCH       = 6

	// TELNET Line Mode options.
	TeloptSLC_BRK         = 2   // Break
	TeloptSLC_IP          = 9   // Interrupt Process
	TeloptSLC_AO          = 10  // Abort Output
	TeloptSLC_AYT         = 11  // Are You There
	TeloptSLC_EOR         = 12  // End Of Record
	TeloptSLC_ABORT       = 13  // Abort
	TeloptSLC_EOF         = 14  // End Of File
	TeloptSLC_SUSP        = 15  // Suspend
	TeloptSLC_EC          = 16  // Erase Character
	TeloptSLC_EL          = 17  // Erase Line
	TeloptSLC_ECHO        = 18  // Echo
	TeloptSLC_REPRINT     = 19  // Reprint
	TeloptSLC_WERASE      = 20  // Word Erase
	TeloptSLC_LNEXT       = 21  // Literal Next
	TeloptSLC_FORW1       = 22  // Forward 1
	TeloptSLC_FORW2       = 23  // Forward 2
	TeloptSLC_BM          = 24  // Back Mode
	TeloptSLC_BEL         = 25  // Bell
	TeloptSLC_XON         = 26  // XON
	TeloptSLC_XOFF        = 27  // XOFF
	TeloptSLC_DO          = 28  // DO
	TeloptSLC_DONT        = 29  // DONT
	TeloptSLC_WILL        = 30  // WILL
	TeloptSLC_WONT        = 31  // WONT
	TeloptSLC_NULL        = 32  // Null
	TeloptSLC_LEVEL       = 33  // Level
	TeloptSLC_CR          = 34  // Carriage Return
	TeloptSLC_LF          = 35  // Line Feed
	TeloptSLC_NUL         = 36  // Null (duplicate)
	TeloptSLC_VT          = 37  // Vertical Tab
	TeloptSLC_BS          = 38  // Backspace
	TeloptSLC_ETX         = 39  // End of Text
	TeloptSLC_EOT         = 40  // End of Transmission
	TeloptSLC_ENQ         = 41  // Enquiry
	TeloptSLC_ACK         = 42  // Acknowledge
	TeloptSLC_NAK         = 43  // Negative Acknowledge
	TeloptSLC_DLE         = 44  // Data Link Escape
	TeloptSLC_DC1         = 45  // Device Control 1
	TeloptSLC_DC2         = 46  // Device Control 2
	TeloptSLC_DC3         = 47  // Device Control 3
	TeloptSLC_DC4         = 48  // Device Control 4
	TeloptSLC_CAN         = 49  // Cancel
	TeloptSLC_EM          = 50  // End of Medium
	TeloptSLC_SUB         = 51  // Substitute
	TeloptSLC_ESC         = 52  // Escape
	TeloptSLC_FS          = 53  // File Separator
	TeloptSLC_GS          = 54  // Group Separator
	TeloptSLC_RS          = 55  // Record Separator
	TeloptSLC_US          = 56  // Unit Separator
	TeloptSLC_DEL         = 57  // Delete
	TeloptSLC_XSTR        = 58  // Extended String
	TeloptSLC_EXT         = 59  // Extended
	TeloptSLC_INFO        = 60  // Info
	TeloptSLC_LNEXT_CHAR  = 61  // Literal Next Character
	TeloptSLC_FORW1_CHAR  = 62  // Forward 1 Character
	TeloptSLC_FORW2_CHAR  = 63  // Forward 2 Character
	TeloptSLC_MCR         = 64  // Multics Carriage Return
	TeloptSLC_MFF         = 65  // Multics Form Feed
	TeloptSLC_MVT         = 66  // Multics Vertical Tab
	TeloptSLC_MBS         = 67  // Multics Backspace
	TeloptSLC_METX        = 68  // Multics End of Text
	TeloptSLC_MEOT        = 69  // Multics End of Transmission
	TeloptSLC_MENQ        = 70  // Multics Enquiry
	TeloptSLC_MACK        = 71  // Multics Acknowledge
	TeloptSLC_MNAK        = 72  // Multics Negative Acknowledge
	TeloptSLC_MDLE        = 73  // Multics Data Link Escape
	TeloptSLC_MDC1        = 74  // Multics Device Control 1
	TeloptSLC_MDC2        = 75  // Multics Device Control 2
	TeloptSLC_MDC3        = 76  // Multics Device Control 3
	TeloptSLC_MDC4        = 77  // Multics Device Control 4
	TeloptSLC_MCAN        = 78  // Multics Cancel
	TeloptSLC_MEM         = 79  // Multics End of Medium
	TeloptSLC_MSUB        = 80  // Multics Substitute
	TeloptSLC_MESC        = 81  // Multics Escape
	TeloptSLC_MFS         = 82  // Multics File Separator
	TeloptSLC_MGS         = 83  // Multics Group Separator
	TeloptSLC_MRS         = 84  // Multics Record Separator
	TeloptSLC_MUS         = 85  // Multics Unit Separator
	TeloptSLC_MDEL        = 86  // Multics Delete
	TeloptSLC_MXSTR       = 87  // Multics Extended String
	TeloptSLC_MEXT        = 88  // Multics Extended
	TeloptSLC_MINFO       = 89  // Multics Info
	TeloptSLC_MLNEXT_CHAR = 90  // Multics Literal Next Character
	TeloptSLC_MFORW1_CHAR = 91  // Multics Forward 1 Character
	TeloptSLC_MFORW2_CHAR = 92  // Multics Forward 2 Character
	TeloptSLC_MAX         = 93  // Max
	TeloptSLC_DEFAULT     = 3   // Default
	TeloptSLC_VALUE       = 2   // Value
	TeloptSLC_CANTCHANGE  = 1   // Can't Change
	TeloptSLC_NOSUPPORT   = 0   // No Support
	TeloptSLC_ACK_VAL     = 0   // Acknowledge Value
	TeloptSLC_NAK_VAL     = 1   // Negative Acknowledge Value
	TeloptSLC_LEVEL_0     = 0   // Level 0
	TeloptSLC_LEVEL_1     = 1   // Level 1
	TeloptSLC_LEVEL_2     = 2   // Level 2
	TeloptSLC_LEVEL_3     = 3   // Level 3
	TeloptSLC_LEVEL_4     = 4   // Level 4
	TeloptSLC_LEVEL_5     = 5   // Level 5
	TeloptSLC_LEVEL_6     = 6   // Level 6
	TeloptSLC_LEVEL_7     = 7   // Level 7
	TeloptSLC_LEVEL_8     = 8   // Level 8
	TeloptSLC_LEVEL_9     = 9   // Level 9
	TeloptSLC_LEVEL_10    = 10  // Level 10
	TeloptSLC_LEVEL_11    = 11  // Level 11
	TeloptSLC_LEVEL_12    = 12  // Level 12
	TeloptSLC_LEVEL_13    = 13  // Level 13
	TeloptSLC_LEVEL_14    = 14  // Level 14
	TeloptSLC_LEVEL_15    = 15  // Level 15
	TeloptSLC_LEVEL_16    = 16  // Level 16
	TeloptSLC_LEVEL_17    = 17  // Level 17
	TeloptSLC_LEVEL_18    = 18  // Level 18
	TeloptSLC_LEVEL_19    = 19  // Level 19
	TeloptSLC_LEVEL_20    = 20  // Level 20
	TeloptSLC_LEVEL_21    = 21  // Level 21
	TeloptSLC_LEVEL_22    = 22  // Level 22
	TeloptSLC_LEVEL_23    = 23  // Level 23
	TeloptSLC_LEVEL_24    = 24  // Level 24
	TeloptSLC_LEVEL_25    = 25  // Level 25
	TeloptSLC_LEVEL_26    = 26  // Level 26
	TeloptSLC_LEVEL_27    = 27  // Level 27
	TeloptSLC_LEVEL_28    = 28  // Level 28
	TeloptSLC_LEVEL_29    = 29  // Level 29
	TeloptSLC_LEVEL_30    = 30  // Level 30
	TeloptSLC_LEVEL_31    = 31  // Level 31
	TeloptSLC_LEVEL_32    = 32  // Level 32
	TeloptSLC_LEVEL_33    = 33  // Level 33
	TeloptSLC_LEVEL_34    = 34  // Level 34
	TeloptSLC_LEVEL_35    = 35  // Level 35
	TeloptSLC_LEVEL_36    = 36  // Level 36
	TeloptSLC_LEVEL_37    = 37  // Level 37
	TeloptSLC_LEVEL_38    = 38  // Level 38
	TeloptSLC_LEVEL_39    = 39  // Level 39
	TeloptSLC_LEVEL_40    = 40  // Level 40
	TeloptSLC_LEVEL_41    = 41  // Level 41
	TeloptSLC_LEVEL_42    = 42  // Level 42
	TeloptSLC_LEVEL_43    = 43  // Level 43
	TeloptSLC_LEVEL_44    = 44  // Level 44
	TeloptSLC_LEVEL_45    = 45  // Level 45
	TeloptSLC_LEVEL_46    = 46  // Level 46
	TeloptSLC_LEVEL_47    = 47  // Level 47
	TeloptSLC_LEVEL_48    = 48  // Level 48
	TeloptSLC_LEVEL_49    = 49  // Level 49
	TeloptSLC_LEVEL_50    = 50  // Level 50
	TeloptSLC_LEVEL_51    = 51  // Level 51
	TeloptSLC_LEVEL_52    = 52  // Level 52
	TeloptSLC_LEVEL_53    = 53  // Level 53
	TeloptSLC_LEVEL_54    = 54  // Level 54
	TeloptSLC_LEVEL_55    = 55  // Level 55
	TeloptSLC_LEVEL_56    = 56  // Level 56
	TeloptSLC_LEVEL_57    = 57  // Level 57
	TeloptSLC_LEVEL_58    = 58  // Level 58
	TeloptSLC_LEVEL_59    = 59  // Level 59
	TeloptSLC_LEVEL_60    = 60  // Level 60
	TeloptSLC_LEVEL_61    = 61  // Level 61
	TeloptSLC_LEVEL_62    = 62  // Level 62
	TeloptSLC_LEVEL_63    = 63  // Level 63
	TeloptSLC_LEVEL_64    = 64  // Level 64
	TeloptSLC_LEVEL_65    = 65  // Level 65
	TeloptSLC_LEVEL_66    = 66  // Level 66
	TeloptSLC_LEVEL_67    = 67  // Level 67
	TeloptSLC_LEVEL_68    = 68  // Level 68
	TeloptSLC_LEVEL_69    = 69  // Level 69
	TeloptSLC_LEVEL_70    = 70  // Level 70
	TeloptSLC_LEVEL_71    = 71  // Level 71
	TeloptSLC_LEVEL_72    = 72  // Level 72
	TeloptSLC_LEVEL_73    = 73  // Level 73
	TeloptSLC_LEVEL_74    = 74  // Level 74
	TeloptSLC_LEVEL_75    = 75  // Level 75
	TeloptSLC_LEVEL_76    = 76  // Level 76
	TeloptSLC_LEVEL_77    = 77  // Level 77
	TeloptSLC_LEVEL_78    = 78  // Level 78
	TeloptSLC_LEVEL_79    = 79  // Level 79
	TeloptSLC_LEVEL_80    = 80  // Level 80
	TeloptSLC_LEVEL_81    = 81  // Level 81
	TeloptSLC_LEVEL_82    = 82  // Level 82
	TeloptSLC_LEVEL_83    = 83  // Level 83
	TeloptSLC_LEVEL_84    = 84  // Level 84
	TeloptSLC_LEVEL_85    = 85  // Level 85
	TeloptSLC_LEVEL_86    = 86  // Level 86
	TeloptSLC_LEVEL_87    = 87  // Level 87
	TeloptSLC_LEVEL_88    = 88  // Level 88
	TeloptSLC_LEVEL_89    = 89  // Level 89
	TeloptSLC_LEVEL_90    = 90  // Level 90
	TeloptSLC_LEVEL_91    = 91  // Level 91
	TeloptSLC_LEVEL_92    = 92  // Level 92
	TeloptSLC_LEVEL_93    = 93  // Level 93
	TeloptSLC_LEVEL_94    = 94  // Level 94
	TeloptSLC_LEVEL_95    = 95  // Level 95
	TeloptSLC_LEVEL_96    = 96  // Level 96
	TeloptSLC_LEVEL_97    = 97  // Level 97
	TeloptSLC_LEVEL_98    = 98  // Level 98
	TeloptSLC_LEVEL_99    = 99  // Level 99
	TeloptSLC_LEVEL_100   = 100 // Level 100
	TeloptSLC_LEVEL_101   = 101 // Level 101
	TeloptSLC_LEVEL_102   = 102 // Level 102
	TeloptSLC_LEVEL_103   = 103 // Level 103
	TeloptSLC_LEVEL_104   = 104 // Level 104
	TeloptSLC_LEVEL_105   = 105 // Level 105
	TeloptSLC_LEVEL_106   = 106 // Level 106
	TeloptSLC_LEVEL_107   = 107 // Level 107
	TeloptSLC_LEVEL_108   = 108 // Level 108
	TeloptSLC_LEVEL_109   = 109 // Level 109
	TeloptSLC_LEVEL_110   = 110 // Level 110
	TeloptSLC_LEVEL_111   = 111 // Level 111
	TeloptSLC_LEVEL_112   = 112 // Level 112
	TeloptSLC_LEVEL_113   = 113 // Level 113
	TeloptSLC_LEVEL_114   = 114 // Level 114
	TeloptSLC_LEVEL_115   = 115 // Level 115
	TeloptSLC_LEVEL_116   = 116 // Level 116
	TeloptSLC_LEVEL_117   = 117 // Level 117
	TeloptSLC_LEVEL_118   = 118 // Level 118
	TeloptSLC_LEVEL_119   = 119 // Level 119
	TeloptSLC_LEVEL_120   = 120 // Level 120
	TeloptSLC_LEVEL_121   = 121 // Level 121
	TeloptSLC_LEVEL_122   = 122 // Level 122
	TeloptSLC_LEVEL_123   = 123 // Level 123
	TeloptSLC_LEVEL_124   = 124 // Level 124
	TeloptSLC_LEVEL_125   = 125 // Level 125
	TeloptSLC_LEVEL_126   = 126 // Level 126
	TeloptSLC_LEVEL_127   = 127 // Level 127
	TeloptSLC_LEVEL_128   = 128 // Level 128
	TeloptSLC_LEVEL_129   = 129 // Level 129
	TeloptSLC_LEVEL_130   = 130 // Level 130
	TeloptSLC_LEVEL_131   = 131 // Level 131
	TeloptSLC_LEVEL_132   = 132 // Level 132
	TeloptSLC_LEVEL_133   = 133 // Level 133
	TeloptSLC_LEVEL_134   = 134 // Level 134
	TeloptSLC_LEVEL_135   = 135 // Level 135
	TeloptSLC_LEVEL_136   = 136 // Level 136
	TeloptSLC_LEVEL_137   = 137 // Level 137
	TeloptSLC_LEVEL_138   = 138 // Level 138
	TeloptSLC_LEVEL_139   = 139 // Level 139
	TeloptSLC_LEVEL_140   = 140 // Level 140
	TeloptSLC_LEVEL_141   = 141 // Level 141
	TeloptSLC_LEVEL_142   = 142 // Level 142
	TeloptSLC_LEVEL_143   = 143 // Level 143
	TeloptSLC_LEVEL_144   = 144 // Level 144
	TeloptSLC_LEVEL_145   = 145 // Level 145
	TeloptSLC_LEVEL_146   = 146 // Level 146
	TeloptSLC_LEVEL_147   = 147 // Level 147
	TeloptSLC_LEVEL_148   = 148 // Level 148
	TeloptSLC_LEVEL_149   = 149 // Level 149
	TeloptSLC_LEVEL_150   = 150 // Level 150
	TeloptSLC_LEVEL_151   = 151 // Level 151
	TeloptSLC_LEVEL_152   = 152 // Level 152
	TeloptSLC_LEVEL_153   = 153 // Level 153
	TeloptSLC_LEVEL_154   = 154 // Level 154
	TeloptSLC_LEVEL_155   = 155 // Level 155
	TeloptSLC_LEVEL_156   = 156 // Level 156
	TeloptSLC_LEVEL_157   = 157 // Level 157
	TeloptSLC_LEVEL_158   = 158 // Level 158
	TeloptSLC_LEVEL_159   = 159 // Level 159
	TeloptSLC_LEVEL_160   = 160 // Level 160
	TeloptSLC_LEVEL_161   = 161 // Level 161
	TeloptSLC_LEVEL_162   = 162 // Level 162
	TeloptSLC_LEVEL_163   = 163 // Level 163
	TeloptSLC_LEVEL_164   = 164 // Level 164
	TeloptSLC_LEVEL_165   = 165 // Level 165
	TeloptSLC_LEVEL_166   = 166 // Level 166
	TeloptSLC_LEVEL_167   = 167 // Level 167
	TeloptSLC_LEVEL_168   = 168 // Level 168
	TeloptSLC_LEVEL_169   = 169 // Level 169
	TeloptSLC_LEVEL_170   = 170 // Level 170
	TeloptSLC_LEVEL_171   = 171 // Level 171
	TeloptSLC_LEVEL_172   = 172 // Level 172
	TeloptSLC_LEVEL_173   = 173 // Level 173
	TeloptSLC_LEVEL_174   = 174 // Level 174
	TeloptSLC_LEVEL_175   = 175 // Level 175
	TeloptSLC_LEVEL_176   = 176 // Level 176
	TeloptSLC_LEVEL_177   = 177 // Level 177
	TeloptSLC_LEVEL_178   = 178 // Level 178
	TeloptSLC_LEVEL_179   = 179 // Level 179
	TeloptSLC_LEVEL_180   = 180 // Level 180
	TeloptSLC_LEVEL_181   = 181 // Level 181
	TeloptSLC_LEVEL_182   = 182 // Level 182
	TeloptSLC_LEVEL_183   = 183 // Level 183
	TeloptSLC_LEVEL_184   = 184 // Level 184
	TeloptSLC_LEVEL_185   = 185 // Level 185
	TeloptSLC_LEVEL_186   = 186 // Level 186
	TeloptSLC_LEVEL_187   = 187 // Level 187
	TeloptSLC_LEVEL_188   = 188 // Level 188
	TeloptSLC_LEVEL_189   = 189 // Level 189
	TeloptSLC_LEVEL_190   = 190 // Level 190
	TeloptSLC_LEVEL_191   = 191 // Level 191
	TeloptSLC_LEVEL_192   = 192 // Level 192
	TeloptSLC_LEVEL_193   = 193 // Level 193
	TeloptSLC_LEVEL_194   = 194 // Level 194
	TeloptSLC_LEVEL_195   = 195 // Level 195
	TeloptSLC_LEVEL_196   = 196 // Level 196
	TeloptSLC_LEVEL_197   = 197 // Level 197
	TeloptSLC_LEVEL_198   = 198 // Level 198
	TeloptSLC_LEVEL_199   = 199 // Level 199
	TeloptSLC_LEVEL_200   = 200 // Level 200
	TeloptSLC_LEVEL_201   = 201 // Level 201
	TeloptSLC_LEVEL_202   = 202 // Level 202
	TeloptSLC_LEVEL_203   = 203 // Level 203
	TeloptSLC_LEVEL_204   = 204 // Level 204
	TeloptSLC_LEVEL_205   = 205 // Level 205
	TeloptSLC_LEVEL_206   = 206 // Level 206
	TeloptSLC_LEVEL_207   = 207 // Level 207
	TeloptSLC_LEVEL_208   = 208 // Level 208
	TeloptSLC_LEVEL_209   = 209 // Level 209
	TeloptSLC_LEVEL_210   = 210 // Level 210
	TeloptSLC_LEVEL_211   = 211 // Level 211
	TeloptSLC_LEVEL_212   = 212 // Level 212
	TeloptSLC_LEVEL_213   = 213 // Level 213
	TeloptSLC_LEVEL_214   = 214 // Level 214
	TeloptSLC_LEVEL_215   = 215 // Level 215
	TeloptSLC_LEVEL_216   = 216 // Level 216
	TeloptSLC_LEVEL_217   = 217 // Level 217
	TeloptSLC_LEVEL_218   = 218 // Level 218
	TeloptSLC_LEVEL_219   = 219 // Level 219
	TeloptSLC_LEVEL_220   = 220 // Level 220
	TeloptSLC_LEVEL_221   = 221 // Level 221
	TeloptSLC_LEVEL_222   = 222 // Level 222
	TeloptSLC_LEVEL_223   = 223 // Level 223
	TeloptSLC_LEVEL_224   = 224 // Level 224
	TeloptSLC_LEVEL_225   = 225 // Level 225
	TeloptSLC_LEVEL_226   = 226 // Level 226
	TeloptSLC_LEVEL_227   = 227 // Level 227
	TeloptSLC_LEVEL_228   = 228 // Level 228
	TeloptSLC_LEVEL_229   = 229 // Level 229
	TeloptSLC_LEVEL_230   = 230 // Level 230
	TeloptSLC_LEVEL_231   = 231 // Level 231
	TeloptSLC_LEVEL_232   = 232 // Level 232
	TeloptSLC_LEVEL_233   = 233 // Level 233
	TeloptSLC_LEVEL_234   = 234 // Level 234
	TeloptSLC_LEVEL_235   = 235 // Level 235
	TeloptSLC_LEVEL_236   = 236 // Level 236
	TeloptSLC_LEVEL_237   = 237 // Level 237
	TeloptSLC_LEVEL_238   = 238 // Level 238
	TeloptSLC_LEVEL_239   = 239 // Level 239
	TeloptSLC_LEVEL_240   = 240 // Level 240
	TeloptSLC_LEVEL_241   = 241 // Level 241
	TeloptSLC_LEVEL_242   = 242 // Level 242
	TeloptSLC_LEVEL_243   = 243 // Level 243
	TeloptSLC_LEVEL_244   = 244 // Level 244
	TeloptSLC_LEVEL_245   = 245 // Level 245
	TeloptSLC_LEVEL_246   = 246 // Level 246
	TeloptSLC_LEVEL_247   = 247 // Level 247
	TeloptSLC_LEVEL_248   = 248 // Level 248
	TeloptSLC_LEVEL_249   = 249 // Level 249
	TeloptSLC_LEVEL_250   = 250 // Level 250
	TeloptSLC_LEVEL_251   = 251 // Level 251
	TeloptSLC_LEVEL_252   = 252 // Level 252
	TeloptSLC_LEVEL_253   = 253 // Level 253
	TeloptSLC_LEVEL_254   = 254 // Level 254
	TeloptSLC_LEVEL_255   = 255 // Level 255

	// IEC sizes.
	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var (
	startTime              = time.Now()
	allowRoot              bool
	logPerm                uint = 0o600
	logDirPerm             uint = 0o750
	altHosts                    = make(map[string]string)
	blacklistedNetworks    []*net.IPNet
	blacklistFile          string
	connections            = make(map[string]*Connection)
	connectionsMutex       sync.Mutex
	consoleInputActive     atomic.Bool
	consoleLogFile         *os.File
	consoleLogMutex        sync.Mutex
	consoleLog             string
	isConsoleLogQuiet      bool
	debugNegotiation       bool
	denyNewConnectionsMode atomic.Bool
	gracefulShutdownMode   atomic.Bool
	idleMax                int
	logDir                 string
	loggingWg              sync.WaitGroup
	noBanner               bool
	noCompress             bool
	noLog                  bool
	showVersion            bool
	shutdownOnce           sync.Once
	shutdownSignal         chan struct{}
	sshAddr                []string
	telnetHostPort         string
	timeMax                int
	whitelistedNetworks    []*net.IPNet
	whitelistFile          string
	issueFile              = "issue.txt"
	denyFile               = "deny.txt"
	blockFile              = "block.txt"
	compressAlgo           string
	compressLevel          string
	emacsKeymap            = map[string]string{
		"\x1b[1;5A": "\x1b\x5b", //    Control-Arrow_Up -> Escape, [
		"\x1b[1;5B": "\x1b\x5d", // Control-Arrrow_Down -> Escape, ]
		"\x1b[1;5C": "\x1b\x66", // Control-Arrow_Right -> Escape, f
		"\x1b[1;5D": "\x1b\x62", //  Control-Arrow_Left -> Escape, b
		"\x1b[1~":   "\x01",     //                Home -> Control-A
		"\x1b[3~":   "\x04",     //              Delete -> Control-D
		"\x1b[4~":   "\x05",     //                 End -> Control-E
		"\x1b[5~":   "\x1b\x76", //             Page_Up -> Escape, v
		"\x1b[6~":   "\x16",     //           Page_Down -> Control-V
		"\x1b[A":    "\x10",     //            Arrow_Up -> Control-P
		"\x1b[B":    "\x0e",     //          Arrow_Down -> Control-N
		"\x1b[C":    "\x06",     //         Arrow_Right -> Control-F
		"\x1b[D":    "\x02",     //          Arrow_Left -> Control-B
	}
	emacsKeymapPrefixes     = make(map[string]bool)
	acceptErrorsTotal       atomic.Uint64
	adminKillsTotal         atomic.Uint64
	altHostRoutesTotal      atomic.Uint64
	exemptedTotal           atomic.Uint64
	idleKillsTotal          atomic.Uint64
	monitorSessionsTotal    atomic.Uint64
	rejectedTotal           atomic.Uint64
	sshConnectionsTotal     atomic.Uint64
	sshHandshakeFailedTotal atomic.Uint64
	sshSessionsTotal        atomic.Uint64
	telnetConnectionsTotal  atomic.Uint64
	telnetFailuresTotal     atomic.Uint64
	timeKillsTotal          atomic.Uint64
)

///////////////////////////////////////////////////////////////////////////////////////////////////

type Connection struct {
	basePath            string
	cancelCtx           context.Context
	cancelFunc          context.CancelFunc
	channel             ssh.Channel
	hostName            string
	ID                  string
	invalidShare        bool
	lastActivityTime    time.Time
	logFile             *os.File
	monitoredConnection *Connection
	monitoring          bool
	shareableUsername   string
	sshConn             *ssh.ServerConn
	sshInTotal          uint64
	sshOutTotal         uint64
	startTime           time.Time
	targetHost          string
	targetPort          int
	totalMonitors       uint64
	userName            string
	emacsKeymapEnabled  bool
	wasMonitored        bool
	termType            string
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type altHostFlag struct{}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (a *altHostFlag) String() string {
	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (a *altHostFlag) Set(value string) error {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid alt-host format: %s, expected sshuser@host:port", value)
	}

	username := parts[0]
	hostPort := parts[1]

	if _, ok := altHosts[username]; ok {
		return fmt.Errorf("duplicate alt-host entry for sshuser: %s", username)
	}

	_, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("invalid host:port in alt-host '%s': %w", value, err)
	}

	altHosts[username] = hostPort

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (a *altHostFlag) Type() string {
	return "string"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type octalPermValue uint

///////////////////////////////////////////////////////////////////////////////////////////////////

func (op *octalPermValue) String() string {
	return fmt.Sprintf("%o", *op)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (op *octalPermValue) Set(s string) error {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid octal permission value: %w", err)
	}
	*op = octalPermValue(v)

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (op *octalPermValue) Type() string {
	return "octal"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func init() {
	pflag.CommandLine.SortFlags = false

	pflag.BoolVarP(&allowRoot,
		"allow-root", "0", false,
		"Allow running as root (UID 0)")

	pflag.StringSliceVarP(&sshAddr,
		"ssh-addr", "l", []string{":2222"},
		"SSH listener address(es)\n   [e.g., \":2222\", \"[::1]:8000\"]\n   (multiple allowed)")
	pflag.Lookup("ssh-addr").DefValue = "\":2222\""

	pflag.BoolVarP(&noBanner,
		"no-banner", "n", false,
		"Disable SSH connection banner")

	pflag.StringVarP(&telnetHostPort,
		"telnet-host", "t", "127.0.0.1:6180",
		"Default TELNET target [host:port]\n  ")

	pflag.VarP(&altHostFlag{},
		"alt-host", "a",
		"Alternate TELNET target(s) [sshuser@host:port]\n   (multiple allowed)")

	pflag.BoolVarP(&debugNegotiation,
		"debug", "d", false,
		"Debug TELNET option negotiation")

	pflag.StringVarP(&logDir,
		"log-dir", "L", "./log",
		"Base directory for logs")

	pflag.BoolVarP(&noLog,
		"no-log", "o", false,
		"Disable all session logging\n   (for console logging, see \"--console-log\")")

	pflag.StringVarP(&consoleLog,
		"console-log", "c", "",
		"Enable console logging [\"quiet\", \"noquiet\"]")

	pflag.StringVarP(&compressAlgo,
		"compress-algo", "C", "gzip",
		"Compression algorithm [\"gzip\", \"xz\", \"zstd\"]\n  ")

	pflag.StringVarP(&compressLevel,
		"compress-level", "s", "normal",
		"Compression level for gzip and zstd algorithms\n   [\"fast\", \"normal\", \"high\"]\n  ")

	pflag.BoolVarP(&noCompress,
		"no-compress", "x", false,
		"Disable session and console log compression")

	pflag.VarP((*octalPermValue)(&logPerm),
		"log-perm", "p",
		"Permissions (octal) for new log files\n   [ e.g., \"600\", \"644\"]")
	pflag.Lookup("log-perm").DefValue = "\"600\""

	pflag.VarP((*octalPermValue)(&logDirPerm),
		"log-dir-perm", "P",
		"Permissions (octal) for new log directories\n   [e.g., \"755\", \"750\"]")
	pflag.Lookup("log-dir-perm").DefValue = "\"750\""

	pflag.IntVarP(&idleMax,
		"idle-max", "i", 0,
		"Maximum connection idle time allowed [seconds]")

	pflag.IntVarP(&timeMax,
		"time-max", "m", 0,
		"Maximum connection link time allowed [seconds]")

	pflag.StringVarP(&blacklistFile,
		"blacklist", "b", "",
		"Enable blacklist [filename] (no default)")

	pflag.StringVarP(&whitelistFile,
		"whitelist", "w", "",
		"Enable whitelist [filename] (no default)")

	pflag.BoolVarP(&showVersion,
		"version", "v", false,
		"Show version information")

	shutdownSignal = make(chan struct{})

	for k := range emacsKeymap {
		for i := 1; i < len(k); i++ {
			emacsKeymapPrefixes[k[:i]] = true
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func shutdownWatchdog() {
	<-shutdownSignal
	loggingWg.Wait()

	if isConsoleLogQuiet {
		fmt.Fprintf(os.Stderr, "%s All connections closed. Exiting.\r\n", nowStamp())
	}

	log.Println("All connections closed. Exiting.")

	os.Exit(0)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	pflag.Parse()

	if consoleLog != "" {
		cl := strings.ToLower(consoleLog)
		if cl != "quiet" && cl != "noquiet" { //nolint:goconst
			log.Fatalf("ERROR: Invalid --console-log value: %s.  Must be 'quiet' or 'noquiet'",
				consoleLog) // LINTED: Fatalf
		}
		isConsoleLogQuiet = (cl == "quiet")
	}

	printVersion()

	if showVersion {
		os.Exit(0)
	}

	if os.Getuid() == 0 && !allowRoot { // LINTED: Fatalf
		log.Fatalf("ERROR: Running as root/UID 0 is not allowed without the -allow-root flag!")
	}

	switch compressAlgo {
	case "gzip", "xz", "zstd":

	default:
		log.Fatalf("ERROR: Invalid --compress-algo: %s", compressAlgo) // LINTED: Fatalf
	}

	switch compressLevel {
	case "fast", "normal", "high": //nolint:goconst

	default:
		log.Fatalf("ERROR: Invalid --compress-level: %s", compressLevel) // LINTED: Fatalf
	}

	setupConsoleLogging()

	if err := os.MkdirAll(logDir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		log.Fatalf("Failed to create log directory: %v", err) // LINTED: Fatalf
	}

	if p, err := filepath.EvalSymlinks(logDir); err == nil {
		logDir = p
	}

	if p, err := filepath.Abs(logDir); err == nil {
		logDir = p
	}

	logDir = filepath.Clean(logDir)

	reloadLists()

	if strings.Contains(telnetHostPort, "@") {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s ERROR: --telnet-host cannot contain a username (e.g., 'user@'). "+
					"Received: %s\r\n", nowStamp(), telnetHostPort)
		}

		log.Fatalf("ERROR: --telnet-host cannot contain a username (e.g., 'user@'). "+
			"Received: %s", telnetHostPort) // LINTED: Fatalf
	}

	if idleMax > 0 && timeMax > 0 && idleMax >= timeMax {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s ERROR: --idle-max (%d) cannot be greater than or equal to --time-max (%d)\r\n",
				nowStamp(), idleMax, timeMax)
		}

		log.Fatalf("ERROR: --idle-max (%d) cannot be greater than or equal to --time-max (%d)",
			idleMax, timeMax) // LINTED: Fatalf
	}

	edSigner, err := loadOrCreateHostKey("ssh_host_ed25519_key.pem", "ed25519")
	if err != nil {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Ed25519 host key error: %v\r\n", nowStamp(), err)
		}

		log.Fatalf("Ed25519 host key error: %v", err) // LINTED: Fatalf
	}

	rsaSigner, err := loadOrCreateHostKey("ssh_host_rsa_key.pem", "rsa")
	if err != nil {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s RSA host key error: %v\r\n", nowStamp(), err)
		}

		log.Fatalf("RSA host key error: %v", err) // LINTED: Fatalf
	}

	for _, addr := range sshAddr {
		go func(addr string) {
			checkPrivilegedPorts(sshAddr)
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				if isConsoleLogQuiet {
					fmt.Fprintf(os.Stderr, "%s LISTEN %s: %v\r\n", nowStamp(), addr, err)
				}

				log.Fatalf("LISTEN %s: %v", addr, err) // LINTED: Fatalf
			}
			defer func() {
				if err := listener.Close(); err != nil {
					log.Printf("Failed to close listener for %s: %v", addr, err)
				}
			}()

			for {
				rawConn, err := listener.Accept()
				if err != nil {
					if gracefulShutdownMode.Load() {
						return
					}

					acceptErrorsTotal.Add(1)
					log.Printf("ACCEPT ERROR: %v", err)

					continue
				}

				go handleConn(rawConn, edSigner, rsaSigner)
			}
		}(addr)
	}

	pid := os.Getpid()

	var startMsg string
	if pid != 0 {
		startMsg = fmt.Sprintf("Starting proxy [PID %d]", pid)
	} else {
		startMsg = "Starting proxy"
	}

	if isConsoleLogQuiet {
		fmt.Fprintf(os.Stderr, "%s %s - Type '?' for help\r\n", nowStamp(), startMsg)
	}

	log.Printf("%s - Type '?' for help", startMsg)

	for _, addr := range sshAddr {
		log.Printf("SSH listener on %s", addr)
	}

	defaultHost, defaultPort, err := parseHostPort(telnetHostPort)
	if err != nil {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Error parsing default TELNET target: %v\r\n",
				nowStamp(), err)
		}

		log.Fatalf("Error parsing default TELNET target: %v", err) // LINTED: Fatalf
	}

	log.Printf("Default TELNET target: %s:%d", defaultHost, defaultPort)

	for user, hostPort := range altHosts {
		log.Printf("Alt target: %s [%s]", hostPort, user)
	}

	runSignalHandlers()

	go handleConsoleInput()

	go shutdownWatchdog()

	go func() {
		if idleMax == 0 {
			return
		}
		checkInterval := 10 * time.Second

		for {
			select {
			case <-shutdownSignal:
				return

			case <-time.After(checkInterval):
				connectionsMutex.Lock()

				for id, conn := range connections {
					if conn.monitoring {
						continue
					}

					idleTime := time.Since(conn.lastActivityTime)
					connUptime := time.Since(conn.startTime)

					if idleMax > 0 && idleTime > time.Duration(idleMax)*time.Second {
						idleKillsTotal.Add(1)
						connUptime := time.Since(conn.startTime)
						log.Printf("IDLEKILL [%s] %s@%s (idle %s, link %s)",
							id, conn.userName, conn.hostName, idleTime.Round(time.Second),
							connUptime.Round(time.Second))

						if _, err := conn.channel.Write([]byte(fmt.Sprintf(
							"\r\n\r\nIDLE TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second)))); err != nil {
							log.Printf(
								"Error writing idle timeout message to channel for %s: %v",
								id, err)
						}

						if err := conn.sshConn.Close(); err != nil {
							log.Printf("Error closing SSH connection for %s: %v", id, err)
						}

						delete(connections, id)
					} else if timeMax > 0 && connUptime > time.Duration(timeMax)*time.Second {
						timeKillsTotal.Add(1)
						connUptime := time.Since(conn.startTime)
						log.Printf("TIMEKILL [%s] %s@%s (link time %s)",
							id, conn.userName, conn.hostName, connUptime.Round(time.Second))

						if _, err := conn.channel.Write([]byte(fmt.Sprintf(
							"\r\n\r\nCONNECTION TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second)))); err != nil {
							log.Printf(
								"Error writing connection timeout message to channel for %s: %v",
								id, err)
						}

						if err := conn.sshConn.Close(); err != nil {
							log.Printf("Error closing SSH connection for %s: %v", id, err)
						}

						delete(connections, id)
					}
				}

				connectionsMutex.Unlock()
			}
		}
	}()

	select {}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isGitSHA(s string) bool {
	match, _ := regexp.MatchString("^[0-9a-f]{40}$", s)

	return match
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func printVersion() {
	versionString := "DPS8M Proxy"

	versionString += func() string {
		if v := getMainModuleVersion(); v != "" {
			return " " + v
		}

		return ""
	}()

	if info, ok := debug.ReadBuildInfo(); ok {
		var date, commit string
		var modified bool

		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.time":
				date = setting.Value

			case "vcs.revision":
				commit = setting.Value

			case "vcs.modified":
				modified = (setting.Value == "true")
			}
		}

		t, err := time.Parse(time.RFC3339, date)
		if err != nil {
			t = time.Now()
		}

		tdate := t.Format("2006-Jan-02")

		if commit != "" && isGitSHA(commit) {
			commit = commit[:7]
		}

		if date != "" && commit != "" {
			if modified {
				versionString += fmt.Sprintf(" (%s g%s+)", tdate, commit)
			} else {
				versionString += fmt.Sprintf(" (%s g%s)", tdate, commit)
			}
		}
	}

	versionString += fmt.Sprintf(" [%s/%s]", runtime.GOOS, runtime.GOARCH)

	if showVersion {
		fmt.Println(versionString)
		fmt.Printf("\r\n")
		printVersionTable()
		fmt.Printf("\r\n")
	} else {
		log.Println(versionString)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConsoleInput() {
	for {
		if consoleInputActive.Load() {
			time.Sleep(100 * time.Millisecond)

			continue
		}

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if !gracefulShutdownMode.Load() {
					log.Println("Console EOF, initiating immediate shutdown.")
					immediateShutdown()
				}

				return
			}
			log.Printf("Console read error: %v", err)

			return
		}

		parts := strings.Fields(input)

		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]

		switch cmd {
		case "?", "h", "H":
			showHelp()

		case "q":
			toggleGracefulShutdown()

		case "d", "D":
			toggleDenyNewConnections()

		case "Q":
			immediateShutdown()

		case "l":
			listConnections(true)

		case "L":
			listConnections(false)

		case "s", "S":
			showStats()

		case "c", "C":
			listConfiguration()

		case "v", "V":
			fmt.Println("")
			originalWriter := log.Writer()

			if consoleLogFile != nil {
				log.SetOutput(io.MultiWriter(os.Stdout))
			} else {
				log.SetOutput(os.Stdout)
			}

			printVersion()
			fmt.Println("")
			printVersionTable()
			fmt.Println("")
			log.SetOutput(originalWriter)

		case "cg", "CG", "cG", "Cg":
			listGoroutines()

		case "k", "K":
			if len(parts) < 2 {
				fmt.Fprintf(os.Stderr, "%s Error: session ID required for 'k' command.\r\n",
					nowStamp())

				continue
			}
			killConnection(parts[1])

		case "r", "R":
			if blacklistFile == "" || whitelistFile == "" {
				if _, err := fmt.Fprintf(
					os.Stdout, "%s Reload requested but no lists enabled.\r\n",
					nowStamp()); err != nil {
					log.Printf("Error writing to stdout: %v", err)
				}
			}
			reloadLists()

		case "xyzzy": // :)
			if isConsoleLogQuiet {
				fmt.Printf("%s Nothing happens.\r\n", nowStamp())
			}
			log.Println("Nothing happens.")

		case "XYZZY": // =)
			if isConsoleLogQuiet {
				fmt.Printf("%s NOTHING HAPPENS.\r\n", nowStamp())
			}
			log.Println("NOTHING HAPPENS.")

		case "":

		default:
			if _, err := fmt.Fprintf(
				os.Stdout, "%s Unknown command: %s\r\n", nowStamp(), cmd); err != nil {
				log.Printf("Error writing to stdout: %v", err)
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showHelp() {
	type row struct{ Key, Description string }

	rows := []row{
		{"c ", "Show Configuration and Status"},
		{"v ", "Show Version Information"},
		{"s ", "Show Connection Statistics"},
		{"l ", "List Active Connections"},
		{"k ", "Kill A Connection"},
		{"d ", "Deny New Connections"},
		{"r ", "Reload Access Control Lists"},
		{"q ", "Start Graceful Shutdown"},
		{"Q ", "Immediate Shutdown"},
	}

	maxKey := len("Key")
	maxDesc := len("Description")

	for _, r := range rows {
		if len(r.Key) > maxKey {
			maxKey = len(r.Key)
		}

		if len(r.Description) > maxDesc {
			maxDesc = len(r.Description)
		}
	}

	border := fmt.Sprintf(
		"\r+=%s=+=%s=+\r\n", strings.Repeat("=", maxKey), strings.Repeat("=", maxDesc),
	)

	fmt.Print("\r\n")
	fmt.Print(border)
	fmt.Printf("\r| %-*s | %-*s |\r\n", maxKey, "Key", maxDesc, "Description")
	fmt.Print(border)

	for _, r := range rows {
		fmt.Printf("\r| %*s | %-*s |\r\n", maxKey, r.Key, maxDesc, r.Description)
	}

	fmt.Print(border)
	fmt.Print("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showStats() {
	type row struct{ Name, Value string }

	rows := []row{
		{"TELNET Total Connections", fmt.Sprintf("%d", telnetConnectionsTotal.Load())},
		{"* TELNET Alt-Host Routings", fmt.Sprintf("%d", altHostRoutesTotal.Load())},
		{"* TELNET Connection Failures", fmt.Sprintf("%d", telnetFailuresTotal.Load())},
		{"SSH Total Connections", fmt.Sprintf("%d", sshConnectionsTotal.Load())},
		{"* SSH User Sessions", fmt.Sprintf("%d", sshSessionsTotal.Load())},
		{"* SSH Monitoring Sessions", fmt.Sprintf("%d", monitorSessionsTotal.Load())},
		{"* SSH Accept Errors", fmt.Sprintf("%d", acceptErrorsTotal.Load())},
		{"* SSH Handshake Errors", fmt.Sprintf("%d", sshHandshakeFailedTotal.Load())},
		{"Connections Killed by Admin", fmt.Sprintf("%d", adminKillsTotal.Load())},
		{"Connections Killed for Idle Time", fmt.Sprintf("%d", idleKillsTotal.Load())},
		{"Connections Killed for Max Time", fmt.Sprintf("%d", timeKillsTotal.Load())},
		{"ACL Rejected Connections", fmt.Sprintf("%d", rejectedTotal.Load())},
		{"* ACL Exempted Connections", fmt.Sprintf("%d", exemptedTotal.Load())},
	}

	maxName := len("Statistic")
	maxVal := len("Value")

	for _, r := range rows {
		if len(r.Name) > maxName {
			maxName = len(r.Name)
		}

		if len(r.Value) > maxVal {
			maxVal = len(r.Value)
		}
	}

	border := fmt.Sprintf(
		"\r+=%s=+=%s=+\r\n", strings.Repeat("=", maxName), strings.Repeat("=", maxVal),
	)

	fmt.Print("\r\n")

	fmt.Print(border)

	fmt.Printf("\r| %-*s | %*s |\r\n", maxName, "Statistic", maxVal, "Value")

	fmt.Print(border)

	for i, r := range rows {
		fmt.Printf("\r| %-*s | %*s |\r\n", maxName, r.Name, maxVal, r.Value)

		switch i {
		case 2, 7, 10, 12:
			fmt.Print(border)
		}
	}
	fmt.Print("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleGracefulShutdown() {
	if gracefulShutdownMode.Load() {
		gracefulShutdownMode.Store(false)

		log.Println("Graceful shutdown cancelled.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s Graceful shutdown cancelled.\r\n", nowStamp())
		}
	} else {
		gracefulShutdownMode.Store(true)

		log.Println("No new connections will be accepted.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s No new connections will be accepted.\r\n", nowStamp())
		}

		log.Println("Graceful shutdown initiated.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s Graceful shutdown initiated.\r\n", nowStamp())
		}

		connectionsMutex.Lock()

		if len(connections) == 0 {
			connectionsMutex.Unlock()

			select {
			case shutdownSignal <- struct{}{}:

			default:
			}
		} else {
			connectionsMutex.Unlock()
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleDenyNewConnections() {
	if denyNewConnectionsMode.Load() {
		denyNewConnectionsMode.Store(false)

		log.Println("Deny connections cancelled.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s Deny connections cancelled.\r\n", nowStamp())
		}
	} else {
		denyNewConnectionsMode.Store(true)

		log.Println("No new connections will be accepted.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s No new connections will be accepted.\r\n", nowStamp())
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func immediateShutdown() {
	shutdownOnce.Do(func() {
		log.Println("Immediate shutdown initiated.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Immediate shutdown initiated.\r\n", nowStamp())
		}

		connectionsMutex.Lock()

		for _, conn := range connections {
			if conn.channel != nil {
				if _, err := conn.channel.Write(
					[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				connUptime := time.Since(conn.startTime)
				log.Printf("LINKDOWN [%s] %s@%s (link time %s)",
					conn.ID, conn.userName, conn.hostName, connUptime.Round(time.Second))
			}

			if conn.cancelFunc != nil {
				conn.cancelFunc()
			}

			if conn.sshConn != nil {
				if err := conn.sshConn.Close(); err != nil {
					log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
				}
			}
		}

		connectionsMutex.Unlock()

		for {
			connectionsMutex.Lock()

			if len(connections) == 0 {
				connectionsMutex.Unlock()

				break
			}

			connectionsMutex.Unlock()

			time.Sleep(100 * time.Millisecond)
		}

		loggingWg.Wait()

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Exiting.\r\n", nowStamp())
		}

		log.Println("Exiting.")

		os.Exit(0)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConnections(truncate bool) {
	connectionsMutex.Lock()

	defer connectionsMutex.Unlock()

	if len(connections) == 0 {
		fmt.Printf("\r%s No active connections.\r\n", nowStamp())

		return
	}

	type row struct {
		ID      string
		Details string
		Link    string
		Idle    string
	}

	userTruncat := false
	rows := make([]row, 0, len(connections))

	for id, conn := range connections {
		user := conn.sshConn.User()

		if truncate && len(user) > 21 {
			userTruncat = true
			user = "..." + user[len(user)-18:]
		}

		var details, idle string
		if conn.monitoring {
			details = fmt.Sprintf("%s@%s -> %s",
				user, conn.sshConn.RemoteAddr(), conn.monitoredConnection.ID)
			idle = "---------"
		} else {
			targetInfo := ""

			if conn.targetHost != "" {
				targetInfo = fmt.Sprintf(" -> %s:%d", conn.targetHost, conn.targetPort)
			}

			details = fmt.Sprintf("%s@%s%s",
				user, conn.sshConn.RemoteAddr(), targetInfo)
			idle = time.Since(conn.lastActivityTime).Round(time.Second).String()
		}

		rows = append(rows, row{
			ID:      id,
			Details: details,
			Link:    time.Since(conn.startTime).Round(time.Second).String(),
			Idle:    idle,
		})
	}

	maxID := len("Session ID")
	maxDetails := len("Connection Details")
	maxLink := len("Link Time")
	maxIdle := len("Idle Time")

	for _, r := range rows {
		if len(r.ID) > maxID {
			maxID = len(r.ID)
		}

		if len(r.Details) > maxDetails {
			maxDetails = len(r.Details)
		}

		if len(r.Link) > maxLink {
			maxLink = len(r.Link)
		}

		if len(r.Idle) > maxIdle {
			maxIdle = len(r.Idle)
		}
	}

	border := fmt.Sprintf(
		"\r+=%s=+=%s=+=%s=+=%s=+\r\n",
		strings.Repeat("=", maxID),
		strings.Repeat("=", maxDetails),
		strings.Repeat("=", maxLink),
		strings.Repeat("=", maxIdle),
	)

	fmt.Printf("\r\n")

	fmt.Print(border)

	fmt.Printf("\r| %-*s | %-*s | %*s | %*s |\r\n",
		maxID, "Session ID", maxDetails, "Connection Details",
		maxLink, "Link Time", maxIdle, "Idle Time")

	fmt.Print(border)

	for _, r := range rows {
		fmt.Printf("\r| %*s | %-*s | %*s | %*s |\r\n",
			maxID, r.ID, maxDetails, r.Details,
			maxLink, r.Link, maxIdle, r.Idle)
	}

	fmt.Print(border)

	if userTruncat {
		fmt.Printf(
			"\r\n* Some Connections Details have been truncated, use 'cg' for wider output.\r\n")
	}

	fmt.Printf("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConfiguration() {
	pid := os.Getpid()

	var b strings.Builder
	const textWidth = 52 // ???

	printRow := func(b *strings.Builder, text string) {
		b.WriteString("| ")
		b.WriteString(text)
		padding := textWidth - len(text)
		if padding < 0 {
			padding = 0
		}
		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(" |\r\n")
	}

	separator := "+======================================================+\r\n"

	b.WriteString("\r\n")
	b.WriteString(separator)

	printRow(&b, fmt.Sprintf("DPS8M Proxy Configuration and Status - PID: %-8d", pid))
	b.WriteString(separator)

	printRow(&b, "SSH listeners on:")

	for _, addr := range sshAddr {
		printRow(&b, "* "+addr)
	}

	b.WriteString(separator)

	printRow(&b, "Default TELNET target: "+telnetHostPort)
	printRow(&b, fmt.Sprintf("Debug TELNET Negotiation: %t", debugNegotiation))

	if len(altHosts) > 0 {
		printRow(&b, "Alt Targets:")

		for user, hostPort := range altHosts {
			printRow(&b, fmt.Sprintf("* %s [%s]", hostPort, user))
		}
	}

	b.WriteString(separator)

	timeMaxStr := "disabled"

	if timeMax > 0 {
		timeMaxStr = fmt.Sprintf("%d seconds", timeMax)
	}

	printRow(&b, "Time Max: "+timeMaxStr)

	idleMaxStr := "disabled"

	if idleMax > 0 {
		idleMaxStr = fmt.Sprintf("%d seconds", idleMax)
	}

	printRow(&b, "Idle Max: "+idleMaxStr)
	b.WriteString(separator)

	printRow(&b, "Log Base Directory: "+logDir)
	printRow(&b, fmt.Sprintf("No Session Logging: %t", noLog))

	if consoleLog != "" {
		var quietMode string
		if isConsoleLogQuiet {
			quietMode = "quiet"
		} else {
			quietMode = "noquiet"
		}
		printRow(&b, "Console Logging: "+quietMode)
	} else {
		printRow(&b, "Console Logging: disabled")
	}

	printRow(&b, fmt.Sprintf("No Log Compression: %t", noCompress))
	printRow(&b, "Compression Algorithm: "+compressAlgo)
	printRow(&b, "Compression Level: "+compressLevel)
	printRow(&b, fmt.Sprintf("Log Permissions: Files: %04o, Dirs: %04o", logPerm, logDirPerm))
	b.WriteString(separator)

	printRow(&b, fmt.Sprintf("Graceful Shutdown: %t", gracefulShutdownMode.Load()))
	printRow(&b, fmt.Sprintf("Deny New Connections: %t", denyNewConnectionsMode.Load()))
	b.WriteString(separator)

	if blacklistFile == "" && len(blacklistedNetworks) == 0 { //nolint:gocritic
		printRow(&b, "Blacklist: 0 entries active")
	} else if whitelistFile != "" && blacklistFile == "" {
		printRow(&b, "Blacklist: Deny all (due to whitelist only)")
	} else {
		printRow(&b, fmt.Sprintf("Blacklist: %d entries active", len(blacklistedNetworks)))
	}

	if whitelistFile == "" {
		printRow(&b, "Whitelist: 0 entries active")
	} else {
		printRow(&b, fmt.Sprintf("Whitelist: %d entries active", len(whitelistedNetworks)))
	}

	b.WriteString(separator)

	uptime := time.Since(startTime)
	uptimeString := fmt.Sprintf("%dh%dm%ds (since %s)",
		int(uptime.Hours())%24, int(uptime.Minutes())%60, int(uptime.Seconds())%60,
		startTime.Format("2006-Jan-02 15:04:24"))

	printRow(&b, "Uptime: "+uptimeString)

	var m runtime.MemStats
	debug.FreeOSMemory()
	runtime.ReadMemStats(&m)
	alloc := float64(m.Alloc)
	sys := float64(m.Sys)
	var allocStr, sysStr string

	switch {
	case alloc >= MiB:
		allocStr = fmt.Sprintf("%.2f MiB", alloc/MiB)

	default:
		allocStr = fmt.Sprintf("%.2f KiB", alloc/KiB)
	}

	switch {
	case sys >= MiB:
		sysStr = fmt.Sprintf("%.2f MiB", sys/MiB)

	default:
		sysStr = fmt.Sprintf("%.2f KiB", sys/KiB)
	}

	memStatsStr := fmt.Sprintf("%s used (of %s reserved)", allocStr, sysStr)
	printRow(&b, "Memory: "+memStatsStr)

	printRow(&b, fmt.Sprintf("Runtime: %d active Goroutines (use 'cg' for details)",
		runtime.NumGoroutine()))

	b.WriteString(separator)

	fmt.Print(b.String())
	fmt.Printf("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func reloadLists() {
	var newBlacklistedNetworks []*net.IPNet
	var newWhitelistedNetworks []*net.IPNet
	var reloadErrors []string

	blacklistReloaded := false
	whitelistReloaded := false

	if blacklistFile != "" {
		networks, err := parseIPListFile(blacklistFile)

		if err != nil {
			reloadErrors = append(
				reloadErrors, fmt.Sprintf("Blacklist rejected: %v", err))
		} else {
			newBlacklistedNetworks = networks
			blacklistReloaded = true
		}
	}

	if whitelistFile != "" {
		networks, err := parseIPListFile(whitelistFile)

		if err != nil {
			reloadErrors = append(
				reloadErrors, fmt.Sprintf("Whitelist rejected: %v", err))
		} else {
			newWhitelistedNetworks = networks
			whitelistReloaded = true
		}
	}

	if len(reloadErrors) > 0 {
		for _, errMsg := range reloadErrors {
			log.Printf("%s", errMsg)
		}

		return
	}

	if blacklistReloaded {
		blacklistedNetworks = newBlacklistedNetworks

		if len(blacklistedNetworks) == 1 {
			log.Printf("Blacklist: 1 entry loaded [%s]",
				blacklistFile)
		} else {
			log.Printf("Blacklist: %d entries loaded [%s]",
				len(blacklistedNetworks), blacklistFile)
		}
	}

	if whitelistReloaded {
		whitelistedNetworks = newWhitelistedNetworks

		if len(whitelistedNetworks) == 1 {
			log.Printf("Whitelist: 1 entry loaded [%s]",
				whitelistFile)
		} else {
			log.Printf("Whitelist: %d entries loaded [%s]",
				len(whitelistedNetworks), whitelistFile)
		}
	}

	if whitelistFile != "" && blacklistFile == "" {
		_, ipv4Net, _ := net.ParseCIDR("0.0.0.0/0")
		_, ipv6Net, _ := net.ParseCIDR("::/0")

		blacklistedNetworks = append(blacklistedNetworks, ipv4Net, ipv6Net)

		log.Println("Blacklist: Blacklisting all host by default")
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func killConnection(id string) {
	connectionsMutex.Lock()

	conn, ok := connections[id]

	connectionsMutex.Unlock()

	if !ok {
		fmt.Fprintf(os.Stderr, "%s Session ID '%s' not found.\r\n", nowStamp(), id)

		return
	}

	if isConsoleLogQuiet {
		if _, err := fmt.Fprintf(
			os.Stderr, "%s Killing connection %s...\r\n", nowStamp(), id); err != nil {
			log.Printf("Error writing to stderr: %v", err)
		}
	}

	if _, err := conn.channel.Write(
		[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n")); err != nil {
		log.Printf("Error writing to channel for %s: %v", conn.ID, err)
	}

	connUptime := time.Since(conn.startTime)

	log.Printf("TERMKILL [%s] %s@%s (link time %s)",
		conn.ID, conn.userName, conn.hostName, connUptime.Round(time.Second))

	adminKillsTotal.Add(1)

	if err := conn.sshConn.Close(); err != nil {
		log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func loadOrCreateHostKey(path, keyType string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(data)
	}

	switch keyType {
	case "rsa":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}

		data := pem.EncodeToMemory(block)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}

		return ssh.ParsePrivateKey(data)

	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}

		block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
		data := pem.EncodeToMemory(block)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}

		return ssh.ParsePrivateKey(data)

	default:
		return nil, fmt.Errorf("UNSUPPORTED KEY TYPE %q", keyType)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConn(rawConn net.Conn, edSigner, rsaSigner ssh.Signer) {
	sid := newSessionID(connections, &connectionsMutex)
	keyLog := []string{}

	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	remoteAddr := rawConn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	if !suppressLogs {
		log.Printf("INITIATE [%s] %s", sid, host)
	}

	sshConnectionsTotal.Add(1)

	config := &ssh.ServerConfig{
		//revive:disable:unused-parameter
		PasswordCallback: func(
			conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) { //nolint:gofumpt
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "password"},
			}, nil
		},
		PublicKeyCallback: func(
			c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) { //nolint:gofumpt
			line := fmt.Sprintf("VALIDATE [%s] %s@%s %q:%s",
				sid, c.User(), c.RemoteAddr(), pubKey.Type(), ssh.FingerprintSHA256(pubKey),
			)

			if !suppressLogs {
				log.Print(line)
			}

			keyLog = append(keyLog, line)

			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "publickey"},
			}, fmt.Errorf("next key")
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) { //nolint:gofumpt
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "keyboard-interactive"},
			}, nil
		},
		//revive:enable:unused-parameter
	}
	config.AddHostKey(edSigner)
	config.AddHostKey(rsaSigner)

	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)
	if err != nil {
		sshHandshakeFailedTotal.Add(1)
		log.Printf("TEARDOWN [%s] HANDSHAKE FAILED: %v", sid, err)

		return
	}

	var authMethod string

	switch sshConn.Permissions.Extensions["auth-method"] {
	case "password":
		authMethod = "password"

	case "publickey":
		authMethod = "publickey"

	case "keyboard-interactive":
		authMethod = "keyboard-interactive"

	default:
		authMethod = "unknown"
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn := &Connection{
		ID:                sid,
		sshConn:           sshConn,
		startTime:         time.Now(),
		lastActivityTime:  time.Now(),
		cancelCtx:         ctx,
		cancelFunc:        cancel,
		userName:          sshConn.User(),
		hostName:          sshConn.RemoteAddr().String(),
		shareableUsername: newShareableUsername(connections, &connectionsMutex),
	}

	connectionsMutex.Lock()

	found := false

	for _, existingConn := range connections {
		if existingConn.shareableUsername == conn.userName {
			conn.monitoring = true
			conn.monitoredConnection = existingConn
			atomic.AddUint64(&existingConn.totalMonitors, 1)
			existingConn.wasMonitored = true
			found = true

			break
		}
	}

	if !found && strings.HasPrefix(conn.userName, "_") && len(conn.userName) == 21 {
		conn.invalidShare = true
	}

	connections[sid] = conn

	connectionsMutex.Unlock()

	defer func() {
		conn.cancelFunc()

		connectionsMutex.Lock()

		delete(connections, sid)

		if gracefulShutdownMode.Load() && len(connections) == 0 {
			connectionsMutex.Unlock()

			select {
			case shutdownSignal <- struct{}{}:

			default:
			}
		} else {
			connectionsMutex.Unlock()
		}

		const unknownHost = "<UNKNOWN>"
		if !suppressLogs {
			host, _, err := net.SplitHostPort(conn.hostName)
			if err != nil {
				log.Printf("TEARDOWN [%s] %s@"+unknownHost,
					sid, func() string {
						if conn.userName == "" {
							return unknownHost
						}

						return conn.userName
					}())
			} else {
				log.Printf("TEARDOWN [%s] %s@%s",
					sid, func() string {
						if conn.userName == "" {
							return unknownHost
						}

						return conn.userName
					}(), host)
			}
		}
	}()

	addr := sshConn.RemoteAddr().String()

	handshakeLog := fmt.Sprintf("VALIDATE [%s] %s@%s \"ssh\":%s",
		sid, func() string {
			if conn.userName == "" {
				return "<UNKNOWN>"
			}

			return conn.userName
		}(), addr, authMethod)

	if !suppressLogs {
		log.Print(handshakeLog)
	}

	keyLog = append(keyLog, handshakeLog)

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			if err := newCh.Reject(
				ssh.UnknownChannelType, "only session allowed"); err != nil {
				log.Printf("Error rejecting channel: %v", err)
			}

			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}

		conn.channel = ch

		go handleSession(conn.cancelCtx, conn, ch, requests, keyLog)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func parseHostPort(hostPort string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", portStr)
	}

	return host, port, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleSession(ctx context.Context, conn *Connection, channel ssh.Channel,
	requests <-chan *ssh.Request, keyLog []string) { //nolint:gofumpt
	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	remoteHost, _, err := net.SplitHostPort(conn.sshConn.RemoteAddr().String())
	if err != nil {
		remoteHost = conn.sshConn.RemoteAddr().String()
	}

	clientIP := net.ParseIP(remoteHost)
	if clientIP == nil {
		if !suppressLogs {
			log.Printf("TEARDOWN [%s] Invalid address: %s", conn.ID, remoteHost)
		}

		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		if err := conn.sshConn.Close(); err != nil {
			log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
		}

		return
	}

	var rejectedByRule string
	for _, ipNet := range blacklistedNetworks {
		if ipNet.Contains(clientIP) {
			rejectedByRule = ipNet.String()

			break
		}
	}

	if rejectedByRule != "" {
		var exemptedByRule string
		for _, ipNet := range whitelistedNetworks {
			if ipNet.Contains(clientIP) {
				exemptedByRule = ipNet.String()

				break
			}
		}

		if exemptedByRule != "" {
			if !suppressLogs {
				log.Printf("EXEMPTED [%s] %s (matched %s)",
					conn.ID, conn.sshConn.RemoteAddr().String(), exemptedByRule)
			}
			exemptedTotal.Add(1)
		} else {
			if !suppressLogs {
				log.Printf("REJECTED [%s] %s (matched %s)",
					conn.ID, conn.sshConn.RemoteAddr().String(), rejectedByRule)
			}
			rejectedTotal.Add(1)

			if raw, err := getFileContent(blockFile, conn.userName); err == nil {
				blockMessageContent := strings.ReplaceAll(
					strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
				if _, err := channel.Write(
					[]byte(blockMessageContent + "\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}
			} else {
				if _, err := channel.Write(
					[]byte("Connection blocked.\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}
			}

			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			if err := conn.sshConn.Close(); err != nil {
				log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
			}

			return
		}
	}

	sendBanner(conn.sshConn, channel, conn)
	sshSessionsTotal.Add(1)
	if conn.monitoring {
		monitorSessionsTotal.Add(1)

		if !suppressLogs {
			log.Printf("UMONITOR [%s] %s -> %s",
				conn.ID, conn.userName, conn.monitoredConnection.ID)
		}

		go func() {
			buf := make([]byte, 1)

			for {
				_, err := channel.Read(buf)
				if err != nil {
					return
				}

				if buf[0] == 0x1D { // Ctrl-]
					if err := channel.Close(); err != nil {
						log.Printf("Error closing channel for %s: %v", conn.ID, err)
					}

					return
				}
			}
		}()

		<-conn.monitoredConnection.cancelCtx.Done()
		dur := time.Since(conn.startTime)

		if _, err := channel.Write([]byte(fmt.Sprintf(
			"\r\nMONITORING SESSION CLOSED (monitored for %s)\r\n\r\n",
			dur.Round(time.Second)))); err != nil {
			log.Printf("Error writing to channel for %s: %v", conn.ID, err)
		}

		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		return
	}

	if gracefulShutdownMode.Load() || denyNewConnectionsMode.Load() {
		if denyMsg, err := getFileContent(denyFile, conn.userName); err == nil {
			txt := strings.ReplaceAll(
				strings.ReplaceAll(string(denyMsg), "\r\n", "\n"), "\n", "\r\n")

			if _, err := channel.Write([]byte("\r\n")); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			if _, err := channel.Write([]byte(txt)); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			if _, err := channel.Write([]byte("\r\n")); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}
		}
		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		return
	}

	if raw, err := getFileContent(issueFile, conn.userName); err == nil {
		txt := strings.ReplaceAll(
			strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")

		if _, err := channel.Write([]byte(txt + "\r\n")); err != nil {
			log.Printf("Error writing to channel for %s: %v", conn.ID, err)
		}
	}

	start := time.Now()
	var sshIn, sshOut, telnetIn, telnetOut uint64

	var logfile *os.File
	var logwriter io.Writer
	var basePath string

	if !noLog {
		logfile, basePath, err = createDatedLog(conn.ID, conn.sshConn.RemoteAddr())
		if err != nil {
			if _, err := fmt.Fprintf(channel, "%v\r\n", err); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			return
		}
		conn.logFile = logfile
		conn.basePath = basePath
		logwriter = logfile

		if _, err := logwriter.Write(
			[]byte(nowStamp() + " Session start\r\n")); err != nil {
			log.Printf("Error writing to log for %s: %v", conn.ID, err)
		}

		for _, line := range keyLog {
			if _, err := logwriter.Write([]byte(nowStamp() + " " + line + "\r\n")); err != nil {
				log.Printf("Error writing to log for %s: %v", conn.ID, err)
			}
		}

		defer func() {
			dur := time.Since(start)
			if _, err := logwriter.Write([]byte(fmt.Sprintf(
				nowStamp()+" Session end (link time %s)\r\n",
				dur.Round(time.Second)))); err != nil {
				log.Printf("Error writing to log: %v", err)
			}
			closeAndCompressLog(logfile, basePath+".log")
		}()
	} else {
		logwriter = io.Discard
	}

	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				termLen := req.Payload[3]
				term := string(req.Payload[4 : 4+termLen])
				conn.termType = term
				if err := req.Reply(true, nil); err != nil {
					log.Printf("Error replying to request: %v", err)
				}

			case "shell":
				if err := req.Reply(true, nil); err != nil {
					log.Printf("Error replying to request: %v", err)
				}

			default:
				if err := req.Reply(false, nil); err != nil {
					log.Printf("Error replying to request: %v", err)
				}
			}
		}
	}()

	var targetHost string
	var targetPort int

	if altHostPort, ok := altHosts[conn.userName]; ok {
		var err error
		targetHost, targetPort, err = parseHostPort(altHostPort)
		if err != nil {
			if _, err := fmt.Fprintf(channel, "Error parsing alt-host for user %s: %v\r\n\r\n",
				conn.userName, err); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			log.Printf("Error parsing alt-host for user %s: %v", conn.userName, err)
			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			return
		}
		log.Printf("ALTROUTE [%s] %s -> %s:%d", conn.ID, conn.userName, targetHost, targetPort)
		conn.targetHost = targetHost
		conn.targetPort = targetPort
		altHostRoutesTotal.Add(1)
	} else {
		var err error
		targetHost, targetPort, err = parseHostPort(telnetHostPort)
		if err != nil {
			if _, err := fmt.Fprintf(
				channel, "Error parsing default telnet-host: %v\r\n\r\n", err); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			log.Printf("Error parsing default telnet-host: %v", err)
			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			return
		}
	}

	if !noLog {
		if _, err := logwriter.Write([]byte(fmt.Sprintf(
			nowStamp()+" Target: %s:%d\r\n", targetHost, targetPort))); err != nil {
			log.Printf("Error writing to log for %s: %v", conn.ID, err)
		}

		if _, err := logwriter.Write([]byte(fmt.Sprintf(
			nowStamp()+" Connection sharing username: '%s'\r\n",
			conn.shareableUsername))); err != nil {
			log.Printf("Error writing to log for %s: %v", conn.ID, err)
		}
	}

	telnetConnectionsTotal.Add(1)
	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		telnetFailuresTotal.Add(1)
		if _, err := fmt.Fprintf(channel, "%v\r\n\r\n", err); err != nil {
			log.Printf("Error writing to channel for %s: %v", conn.ID, err)
		}

		log.Printf("%v", err)
		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		return
	}

	if tcp2, ok := remote.(*net.TCPConn); ok {
		_ = tcp2.SetNoDelay(true)
	}

	defer func() {
		if err := remote.Close(); err != nil {
			log.Printf("Error closing remote connection for %s: %v", conn.ID, err)
		}
	}()

	negotiateTelnet(remote, channel, logwriter, conn)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		var menuMode bool
		var escSequence []byte
		var escTimer <-chan time.Time
		reader := bufio.NewReader(channel)

		byteChan := make(chan byte)
		errorChan := make(chan error)

		go func() {
			for {
				select {
				case <-ctx.Done():
					close(byteChan)
					close(errorChan)

					return

				default:
					b, err := reader.ReadByte()
					if err != nil {
						errorChan <- err
						close(byteChan)
						close(errorChan)

						return
					}
					byteChan <- b
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				if len(escSequence) > 0 {
					if _, err := remote.Write(escSequence); err != nil {
						log.Printf("Error writing to remote for %s: %v", conn.ID, err)
					}

					if _, err := logwriter.Write(escSequence); err != nil {
						log.Printf("Error writing to log for %s: %v", conn.ID, err)
					}
				}

				return

			case <-escTimer:
				m, err := remote.Write(escSequence)
				if err != nil {
					log.Printf("Error writing to remote for %s: %v", conn.ID, err)
				}

				atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec
				if _, err := logwriter.Write(escSequence); err != nil {
					log.Printf("Error writing to log for %s: %v", conn.ID, err)
				}

				escSequence = nil
				escTimer = nil

			case b := <-byteChan:
				conn.lastActivityTime = time.Now()
				atomic.AddUint64(&sshIn, 1)
				atomic.AddUint64(&conn.sshInTotal, 1)

				if menuMode {
					handleMenuSelection(b, conn, channel, remote, logwriter,
						&sshIn, &sshOut, &telnetIn, &telnetOut, start)
					menuMode = false

					continue
				}

				if b == 0x1d { // Ctrl-]
					showMenu(channel)
					menuMode = true
					escSequence = nil
					escTimer = nil

					continue
				}

				if len(escSequence) > 0 { //nolint:gocritic
					escSequence = append(escSequence, b)
					if conn.emacsKeymapEnabled {
						if replacement, ok := //nolint:gofumpt,nolintlint
							emacsKeymap[string(escSequence)]; ok {
							m, err := remote.Write([]byte(replacement))
							if err != nil {
								log.Printf("Error writing to remote for %s: %v", conn.ID, err)
							}

							atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

							if _, err := logwriter.Write([]byte(replacement)); err != nil {
								log.Printf("Error writing to log for %s: %v", conn.ID, err)
							}

							escSequence = nil
							escTimer = nil
						} else if _, isPrefix := //nolint:gofumpt,nolintlint
							emacsKeymapPrefixes[string(escSequence)]; isPrefix {
							escTimer = time.After(50 * time.Millisecond)
						} else {
							m, err := remote.Write(escSequence)
							if err != nil {
								log.Printf("Error writing to remote for %s: %v", conn.ID, err)
							}

							atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

							if _, err := logwriter.Write(escSequence); err != nil {
								log.Printf("Error writing to log for %s: %v", conn.ID, err)
							}

							escSequence = nil
							escTimer = nil
						}
					} else {
						m, err := remote.Write(escSequence)
						if err != nil {
							log.Printf("Error writing to remote for %s: %v", conn.ID, err)
						}

						atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

						if _, err := logwriter.Write(escSequence); err != nil {
							log.Printf("Error writing to log for %s: %v", conn.ID, err)
						}

						escSequence = nil
						escTimer = nil
					}
				} else if b == 0x1b && conn.emacsKeymapEnabled {
					escSequence = append(escSequence, b)
					escTimer = time.After(50 * time.Millisecond)
				} else {
					m, err := remote.Write([]byte{b})
					if err != nil {
						log.Printf("Error writing to remote for %s: %v", conn.ID, err)
					}

					atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

					if _, err := logwriter.Write([]byte{b}); err != nil {
						log.Printf("Error writing to log for %s: %v", conn.ID, err)
					}
				}

			case err := <-errorChan:
				if len(escSequence) > 0 {
					if _, err := remote.Write(escSequence); err != nil {
						log.Printf("Error writing to remote for %s: %v", conn.ID, err)
					}

					if _, err := logwriter.Write(escSequence); err != nil {
						log.Printf("Error writing to log for %s: %v", conn.ID, err)
					}
				}
				if !errors.Is(err, io.EOF) {
					log.Printf("SSH channel read error: %v", err)
				}

				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)

		for {
			if err := remote.SetReadDeadline(
				time.Now().Add(100 * time.Millisecond)); err != nil {
				log.Printf("Error setting read deadline for %s: %v", conn.ID, err)
			}
			n, err := remote.Read(buf)
			if err != nil {
				var netErr net.Error

				if errors.As(err, &netErr) && netErr.Timeout() {
					select {
					case <-ctx.Done():
						return

					default:
					}

					continue
				}

				dur := time.Since(start)
				log.Printf("DETACHED [%s] %s@%s (link time %s)",
					conn.ID, conn.userName, conn.hostName, dur.Round(time.Second))

				if _, err := channel.Write([]byte(fmt.Sprintf(
					"\r\nCONNECTION CLOSED (link time %s)\r\n\r\n",
					dur.Round(time.Second)))); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				inRateSSH := uint64(float64(atomic.LoadUint64(&sshIn)) / dur.Seconds())
				outRateSSH := uint64(float64(atomic.LoadUint64(&sshOut)) / dur.Seconds())
				inRateNVT := uint64(float64(atomic.LoadUint64(&telnetIn)) / dur.Seconds())
				outRateNVT := uint64(float64(atomic.LoadUint64(&telnetOut)) / dur.Seconds())

				if _, err := channel.Write([]byte(fmt.Sprintf(
					">> SSH - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
					atomic.LoadUint64(&sshIn), atomic.LoadUint64(&sshOut),
					inRateSSH, outRateSSH))); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				if _, err := channel.Write([]byte(fmt.Sprintf(
					">> NVT - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
					atomic.LoadUint64(&telnetIn), atomic.LoadUint64(&telnetOut),
					inRateNVT, outRateNVT))); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				if _, err := channel.Write([]byte("\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				if err := channel.Close(); err != nil {
					log.Printf("Error closing channel for %s: %v", conn.ID, err)
				}

				conn.sshInTotal = sshIn
				conn.sshOutTotal = sshOut

				return
			}

			if n > 0 {
				atomic.AddUint64(&telnetIn, uint64(n))
				atomic.AddUint64(&conn.sshInTotal, uint64(n))
				fwd := bytes.ReplaceAll(buf[:n], []byte{0}, []byte{})

				atomic.AddUint64(&sshOut, uint64(len(fwd)))
				atomic.AddUint64(&conn.sshOutTotal, uint64(len(fwd)))

				if _, err := channel.Write(fwd); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				connectionsMutex.Lock()

				for _, c := range connections {
					if c.monitoring && c.monitoredConnection.ID == conn.ID {
						if _, err := c.channel.Write(fwd); err != nil {
							log.Printf("Error writing to channel for %s: %v", c.ID, err)
						}
					}
				}

				connectionsMutex.Unlock()

				if _, err := logwriter.Write(buf[:n]); err != nil {
					log.Printf("Error writing to log for %s: %v", conn.ID, err)
				}

				conn.lastActivityTime = time.Now()
			}
		}
	}()

	wg.Wait()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendBanner(sshConn *ssh.ServerConn, ch ssh.Channel, conn *Connection) {
	if noBanner {
		return
	}

	host, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	names, _ := net.DefaultResolver.LookupAddr(ctx, host)

	var origin string

	if len(names) > 0 {
		origin = fmt.Sprintf("%s [%s]", strings.TrimSuffix(names[0], "."), host)
	} else {
		origin = host
	}

	now := nowStamp()

	if _, err := fmt.Fprintf(
		ch, "Session with %s active at %s.\r\n", origin, now); err != nil {
		log.Printf("Error writing session active message to channel: %v", err)
	}

	if conn.monitoring {
		if _, err := fmt.Fprint(
			ch, "This is a READ-ONLY shared monitoring session.\r\n"); err != nil {
			log.Printf("Error writing monitoring session message to channel: %v", err)
		}

		if _, err := fmt.Fprint(ch, "Send Control-] to disconnect.\r\n"); err != nil {
			log.Printf("Error writing disconnect message to channel: %v", err)
		}
	} else if conn.invalidShare {
		if _, err := fmt.Fprintf(
			ch, "The username '%s' was NOT active for session sharing!\r\n",
			conn.userName); err != nil {
			log.Printf("Error writing invalid share message to channel: %v", err)
		}
	}

	if _, err := fmt.Fprint(ch, "\r\n"); err != nil {
		log.Printf("Error writing newline to channel: %v", err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func negotiateTelnet(remote net.Conn, ch ssh.Channel, logw io.Writer, conn *Connection) {
	type telnetState struct {
		weWill   bool
		weDo     bool
		theyWill bool
		theyDo   bool
	}

	telnetStates := make(map[byte]*telnetState)
	// Options that we do not support and will always reject.
	var unsupportedOptions = []byte{
		TeloptATCP,
		TeloptAuth,
		TeloptCompPort,
		TeloptEncrypt,
		TeloptGMCP,
		TeloptLineMode,
		TeloptMCCP2,
		TeloptMCCP3,
		TeloptMSP,
		TeloptMSSP,
		TeloptMXP,
		TeloptNewEnviron,
		TeloptOldEnviron,
		TeloptRM,
		TeloptTS,
		TeloptXDisplay,
		TeloptStatus,
	}

	// Keep track of options we've already rejected to avoid redundant responses.
	rejectedOptions := make(map[byte]bool)

	// Initialize states for common options
	for _, opt := range []byte{
		TeloptATCP,
		TeloptAuth,
		TeloptBinary,
		TeloptCompPort,
		TeloptEcho,
		TeloptEncrypt,
		TeloptGMCP,
		TeloptLineMode,
		TeloptMCCP2,
		TeloptMCCP3,
		TeloptMSP,
		TeloptMSSP,
		TeloptMXP,
		TeloptNAWS,
		TeloptNewEnviron,
		TeloptOldEnviron,
		TeloptRM,
		TeloptSuppressGoAhead,
		TeloptTS,
		TeloptXDisplay,
	} {
		telnetStates[opt] = &telnetState{}
	}

	if err := remote.SetReadDeadline(time.Now().Add(time.Second / 3)); err != nil {
		log.Printf("Error setting read deadline: %v", err)
	}

	defer func() {
		if err := remote.SetReadDeadline(time.Time{}); err != nil {
			log.Printf("Error clearing read deadline: %v", err)
		}
	}()

	buf := make([]byte, 512)

	for {
		n, err := remote.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}

			return
		}

		i := 0
		for i < n {
			if buf[i] == TelcmdIAC {
				if i+2 < n {
					cmd, opt := buf[i+1], buf[i+2]
					writeNegotiation(ch, logw,
						"[RCVD "+cmdName(cmd)+" "+optName(opt)+"]", conn.userName)

					state, ok := telnetStates[opt]
					if !ok {
						state = &telnetState{}
						telnetStates[opt] = state
					}

					switch cmd {
					case TelcmdWILL:
						if contains(unsupportedOptions, opt) {
							sendIAC(remote, TelcmdDONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdDONT)+" "+optName(opt)+"]", conn.userName)
							rejectedOptions[opt] = true // Still mark as rejected to avoid excessive logging if we re-introduce the check
						} else if !state.theyWill {
							state.theyWill = true
							sendIAC(remote, TelcmdDO, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdDO)+" "+optName(opt)+"]", conn.userName)
						}

					case TelcmdWONT:
						if state.theyWill {
							state.theyWill = false
							sendIAC(remote, TelcmdDONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdDONT)+" "+optName(opt)+"]", conn.userName)
						}

					case TelcmdDO:
						if opt == TeloptTTYPE {
							if !state.weWill {
								state.weWill = true
								sendIAC(remote, TelcmdWILL, TeloptTTYPE)
								writeNegotiation(ch, logw,
									"[SENT "+cmdName(TelcmdWILL)+" "+optName(TeloptTTYPE)+"]", conn.userName)
							}
						} else if contains(unsupportedOptions, opt) {
							sendIAC(remote, TelcmdWONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdWONT)+" "+optName(opt)+"]", conn.userName)
							rejectedOptions[opt] = true // Still mark as rejected
						} else if !state.theyDo {
							state.theyDo = true
							sendIAC(remote, TelcmdWILL, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdWILL)+" "+optName(opt)+"]", conn.userName)
						}

					case TelcmdDONT:
						if state.theyDo {
							state.theyDo = false
							sendIAC(remote, TelcmdWONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdWONT)+" "+optName(opt)+"]", conn.userName)
						}

					case TelcmdSB: // Subnegotiation
						// Find the end of the subnegotiation
						seIndex := -1
						for j := i + 3; j < n-1; j++ {
							if buf[j] == TelcmdIAC && buf[j+1] == TelcmdSE {
								seIndex = j
								break
							}
						}

						if seIndex != -1 {
							subOpt := buf[i+2]
							subData := buf[i+3 : seIndex]

							writeNegotiation(ch, logw,
								"[RCVD SB "+optName(subOpt)+" ... IAC SE]", conn.userName)

							if subOpt == TeloptTTYPE && len(subData) > 0 && subData[0] == TelnetSend {
								// Respond with terminal type if available
								if conn.termType != "" {
									data := []byte{TelcmdIAC, TelcmdSB, TeloptTTYPE, TelnetIs}
									data = append(data, []byte(conn.termType)...)
									data = append(data, TelcmdIAC, TelcmdSE)
									if _, err := remote.Write(data); err != nil {
										log.Printf("Error writing Telnet TTYPE response: %v", err)
									}
									writeNegotiation(ch, logw,
										"[SENT SB "+optName(TeloptTTYPE)+" IS "+conn.termType+" IAC SE]", conn.userName)
								} else {
									sendIAC(remote, TelcmdNOP)
									writeNegotiation(ch, logw,
										"[SENT NOP (no terminal type available)]", conn.userName)
								}
							} else if contains(unsupportedOptions, subOpt) {
								// If we don't support the option, ignore its subnegotiation
								i = seIndex + 2 // Move past IAC SE
								continue
							}

							switch subOpt {
							case TeloptNAWS:
								if len(subData) >= 4 {
									width := int(subData[0])<<8 | int(subData[1])
									height := int(subData[2])<<8 | int(subData[3])
									log.Printf("NAWS received: %dx%d", width, height)
								}
							}
							i = seIndex + 2 // Move past IAC SE
							continue
						}

					default:
						// Unknown command, skip
					}
					i += 3
				} else if i+1 < n && buf[i+1] == TelcmdSB { // IAC SB without SE
					// Incomplete subnegotiation, skip IAC SB
					writeNegotiation(ch, logw, "[RCVD IAC SB (incomplete)]", conn.userName)
					i += 2
				} else { // IAC followed by single byte or end of buffer
					writeNegotiation(ch, logw, "[RCVD IAC (incomplete)]", conn.userName)
					i += 1
				}
			} else {
				_, _ = ch.Write(buf[i : i+1])
				_, _ = logw.Write(buf[i : i+1])
				i++
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func writeNegotiation(ch io.Writer, logw io.Writer, line string, username string) {
		msg := line
		if debugNegotiation {
			msg = fmt.Sprintf("%s %s", username, line)
		}
		msg += "\r\n"

		if _, err := logw.Write([]byte(msg)); err != nil {
			log.Printf("Error writing negotiation message to log: %v", err)
		}

		if debugNegotiation {
			if _, err := ch.Write([]byte(msg)); err != nil {
				log.Printf("Error writing negotiation message to channel: %v", err)
			}
		}
	}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendIAC(w io.Writer, cmd byte, opts ...byte) {
	data := []byte{TelcmdIAC, cmd}
	data = append(data, opts...)
	if _, err := w.Write(data); err != nil {
		log.Printf("Error writing Telnet command to writer: %v", err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func cmdName(b byte) string {
	switch b {
	case TelcmdDO:
		return "DO"

	case TelcmdDONT:
		return "DONT"

	case TelcmdWILL:
		return "WILL"

	case TelcmdWONT:
		return "WONT"
	}

	return fmt.Sprintf("CMD_%d", b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func optName(b byte) string {
	switch b {
	case TeloptBinary:
		return "BINARY"

	case TeloptEcho:
		return "ECHO"

	case TeloptSuppressGoAhead:
		return "SUPPRESS GO AHEAD"

	case TeloptStatus:
		return "STATUS"

	case TeloptTimingMark:
		return "TIMING MARK"

	case TeloptNAWS:
		return "NAWS"

	case TeloptTS:
		return "TERMINAL SPEED"

	case TeloptRM:
		return "REMOTE FLOW CONTROL"

	case TeloptNewEnviron:
		return "NEW ENVIRON"

	case TeloptTTYPE:
		return "TERMINAL TYPE"

	case TeloptXDisplay:
		return "X DISPLAY"

	case TeloptOldEnviron:
		return "OLD ENVIRON"

	case TeloptAuth:
		return "AUTHENTICATION"

	case TeloptEncrypt:
		return "ENCRYPT"

	case TeloptCompPort:
		return "COM PORT CONTROL"

	case TeloptMSSP:
		return "MSSP"

	case TeloptMCCP2:
		return "MCCP2"

	case TeloptMCCP3:
		return "MCCP3"

	case TeloptMSP:
		return "MSP"

	case TeloptMXP:
		return "MXP"

	case TeloptATCP:
		return "ATCP"

	case TeloptGMCP:
		return "GMCP"

	case TeloptLineMode:
		return "LINE MODE"

	case TeloptEnd:
		return "END"
	}

	return fmt.Sprintf("OPT_%d", b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showMenu(ch ssh.Channel) {
	menu := "\r                         \r\n" +
		"\r +=====+===============+ \r\n" +
		"\r | Key | TELNET Action | \r\n" +
		"\r +=====+===============+ \r\n" +
		"\r |  A  | Send AYT      | \r\n" +
		"\r |  B  | Send Break    | \r\n" +
		"\r |  K  | Toggle Keymap | \r\n" +
		"\r |  N  | Send NOP      | \r\n" +
		"\r |  S  | Show Status   | \r\n" +
		"\r |  X  | Disconnect    | \r\n" +
		"\r |  ]  | Send Ctrl-]   | \r\n" +
		"\r +=====+===============+ \r\n"

	if _, err := ch.Write([]byte(menu)); err != nil {
		log.Printf("Error writing menu to channel: %v", err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleMenuSelection(sel byte, conn *Connection, ch ssh.Channel, remote net.Conn,
	logw io.Writer, sshIn, sshOut, telnetIn, telnetOut *uint64, start time.Time) { //nolint:gofumpt
	switch sel {
	case 'a', 'A':
		sendIAC(remote, TelcmdAYT)
		if _, err := logw.Write([]byte{TelcmdIAC, TelcmdAYT}); err != nil {
			log.Printf("Error writing AYT to log: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n>> Sent AYT\r\n")); err != nil {
			log.Printf("Error writing 'Sent AYT' message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing 'BACK TO HOST' message after AYT to channel: %v", err)
		}

	case 'b', 'B':
		sendIAC(remote, 243) // BREAK
		if _, err := logw.Write([]byte{TelcmdIAC, 243}); err != nil {
			log.Printf("Error writing BREAK to log: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n>> Sent BREAK\r\n")); err != nil {
			log.Printf("Error writing 'Sent BREAK' message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing '[BACK TO HOST]' message to channel: %v", err)
		}

	case 'k', 'K':
		conn.emacsKeymapEnabled = !conn.emacsKeymapEnabled
		if conn.emacsKeymapEnabled {
			if _, err := ch.Write([]byte("\r\n>> Emacs keymap ENABLED\r\n")); err != nil {
				log.Printf("Error writing 'Emacs keymap ENABLED' message to channel: %v", err)
			}
		} else {
			if _, err := ch.Write([]byte("\r\n>> Emacs keymap DISABLED\r\n")); err != nil {
				log.Printf("Error writing 'Emacs keymap DISABLED' message to channel: %v", err)
			}
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing '[BACK TO HOST]' message to channel: %v", err)
		}

	case 'n', 'N':
		sendIAC(remote, TelcmdNOP)
		if _, err := logw.Write([]byte{TelcmdIAC, TelcmdNOP}); err != nil {
			log.Printf("Error writing NOP to log: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n>> Sent NOP\r\n")); err != nil {
			log.Printf("Error writing 'Sent NOP' message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing '[BACK TO HOST]' message to channel: %v", err)
		}

	case 's', 'S':
		dur := time.Since(start)
		if _, err := ch.Write([]byte("\r\n")); err != nil {
			log.Printf("Error writing newline to channel: %v", err)
		}

		if _, err := ch.Write([]byte(fmt.Sprintf(
			">> LNK - Username '%s' can be used to share this session.\r\n",
			conn.shareableUsername))); err != nil {
			log.Printf("Error writing sharable username to channel: %v", err)
		}

		if conn.wasMonitored {
			connectionsMutex.Lock()

			currentMonitors := 0

			for _, c := range connections {
				if c.monitoring && c.monitoredConnection.ID == conn.ID {
					currentMonitors++
				}
			}

			connectionsMutex.Unlock()

			timesStr := "times"
			if conn.totalMonitors == 1 {
				timesStr = "time"
			}

			userStr := "users"
			if currentMonitors == 1 {
				userStr = "user"
			}

			if _, err := ch.Write([]byte(fmt.Sprintf(
				">> MON - Shared session has been viewed %d %s; %d %s currently online.\r\n",
				conn.totalMonitors, timesStr, currentMonitors, userStr))); err != nil {
				log.Printf("Error writing shared session information to channel: %v", err)
			}
		}

		inSSH := atomic.LoadUint64(sshIn)
		outSSH := atomic.LoadUint64(sshOut)
		inNVT := atomic.LoadUint64(telnetIn)
		outNVT := atomic.LoadUint64(telnetOut)

		inRateSSH := uint64(float64(atomic.LoadUint64(sshIn)) / dur.Seconds())
		outRateSSH := uint64(float64(atomic.LoadUint64(sshOut)) / dur.Seconds())
		inRateNVT := uint64(float64(atomic.LoadUint64(telnetIn)) / dur.Seconds())
		outRateNVT := uint64(float64(atomic.LoadUint64(telnetOut)) / dur.Seconds())

		if _, err := ch.Write([]byte(fmt.Sprintf(
			">> SSH - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
			inSSH, outSSH, inRateSSH, outRateSSH))); err != nil {
			log.Printf("Error writing SSH statistics to channel: %v", err)
		}

		if _, err := ch.Write([]byte(fmt.Sprintf(
			">> NVT - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
			inNVT, outNVT, inRateNVT, outRateNVT))); err != nil {
			log.Printf("Error writing NVT statistics to channel: %v", err)
		}

		keymapStatus := ""
		if conn.emacsKeymapEnabled {
			keymapStatus = " (Emacs keymap enabled)"
		}

		if _, err := ch.Write([]byte(">> LNK - link time: " +
			dur.Round(time.Second).String() + keymapStatus + "\r\n")); err != nil {
			log.Printf("Error writing link time and keymap status message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing 'BACK TO HOST' message after link time to channel: %v", err)
		}

	case 'x', 'X':
		if _, err := ch.Write([]byte("\r\n>> DISCONNECTING...\r\n")); err != nil {
			log.Printf("Error writing 'DISCONNECTING' message to channel: %v", err)
		}

		if err := ch.Close(); err != nil {
			log.Printf("Error closing channel: %v", err)
		}

	case ']':
		sendIAC(remote, 0x1d) // Ctrl-]
		if _, err := logw.Write([]byte{0x1d}); err != nil {
			log.Printf("Error writing Ctrl-] to log: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n>> Sent Ctrl-]\r\n")); err != nil {
			log.Printf("Error writing 'Sent Ctrl-]' message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing '[BACK TO HOST]' message to channel: %v", err)
		}

	default:
		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing 'BACK TO HOST' message for default case to channel: %v", err)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func createDatedLog(sid string, addr net.Addr) (*os.File, string, error) {
	host, _, _ := net.SplitHostPort(addr.String())
	ipDir := sanitizeIP(host)
	now := time.Now()
	dir := filepath.Join(
		logDir,
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", now.Month()),
		fmt.Sprintf("%02d", now.Day()),
	)

	if err := os.MkdirAll(dir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		return nil, "", err
	}

	dir = filepath.Join(dir, ipDir)

	if err := os.MkdirAll(dir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		return nil, "", err
	}

	ts := now.Format("150405")
	files, _ := os.ReadDir(dir)
	maxSeq := 0
	prefix := ts + "_" + sid + "_"

	for _, f := range files {
		if strings.HasPrefix(f.Name(), prefix) {
			parts := strings.SplitN(f.Name()[len(prefix):], ".", 2)

			if n, err := strconv.Atoi(parts[0]); err == nil && n > maxSeq {
				maxSeq = n
			}
		}
	}

	loggingWg.Add(1)

	seq := maxSeq + 1
	base := fmt.Sprintf("%s_%s_%d", ts, sid, seq)
	pathBase := filepath.Join(dir, base)
	f, err := os.OpenFile(pathBase+".log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(logPerm)) //nolint:gosec

	return f, pathBase, err
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func closeAndCompressLog(logfile *os.File, logFilePath string) {
	defer loggingWg.Done()
	err := logfile.Close()
	if err != nil {
		return
	}

	if noCompress {
		return
	}

	compressLogFile(logFilePath)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sanitizeIP(s string) string {
	return strings.NewReplacer(":", "_", ".", "_").Replace(s)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func newSessionID(connections map[string]*Connection, mutex *sync.Mutex) string {
	for {
		b := make([]byte, 3)

		if _, err := rand.Read(b); err != nil {
			log.Printf("Error reading random bytes for session ID: %v", err)
		}

		id := hex.EncodeToString(b)

		mutex.Lock()

		_, exists := connections[id]

		mutex.Unlock()

		if !exists {
			return id
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func newShareableUsername(connections map[string]*Connection, mutex *sync.Mutex) string {
	const chars = "abcdghkmnprsvwxyzACDFGJKMNPRSTVXY345679"
	for {
		b := make([]byte, 20)

		if _, err := rand.Read(b); err != nil {
			log.Printf("Error reading random bytes for shareable username: %v", err)
		}

		for i, v := range b {
			b[i] = chars[v%byte(len(chars))]
		}

		username := "_" + string(b)

		mutex.Lock()

		found := false

		for _, conn := range connections {
			if conn.shareableUsername == username {
				found = true

				break
			}
		}

		mutex.Unlock()

		if !found {
			return username
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func nowStamp() string {
	return time.Now().Format("2006/01/02 15:04:05")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getFileContent(baseFilename, username string) ([]byte, error) {
	userSpecificFile := fmt.Sprintf(
		"%s-%s.txt", strings.TrimSuffix(baseFilename, ".txt"), username)
	content, err := os.ReadFile(userSpecificFile)
	if err == nil {
		return content, nil
	}

	return os.ReadFile(baseFilename)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getConsoleLogPath(t time.Time) string {
	return filepath.Join(
		logDir,
		fmt.Sprintf("%04d", t.Year()),
		fmt.Sprintf("%02d", t.Month()),
		fmt.Sprintf("%02d", t.Day()),
		"console.log",
	)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func setupConsoleLogging() {
	if consoleLog == "" {
		return
	}

	rotateConsoleLog()

	go func() {
		for {
			now := time.Now()
			nextMidnight := now.Add(24 * time.Hour).Truncate(24 * time.Hour)
			time.Sleep(time.Until(nextMidnight))

			rotateConsoleLog()
		}
	}()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func rotateConsoleLog() {
	debug.FreeOSMemory()

	consoleLogMutex.Lock()

	defer consoleLogMutex.Unlock()

	if consoleLogFile != nil {
		if !noCompress {
			yesterdayLogPath := getConsoleLogPath(time.Now().AddDate(0, 0, -1))
			compressLogFile(yesterdayLogPath)
		}

		if err := consoleLogFile.Close(); err != nil {
			log.Printf("Error closing console log file: %v", err)
		}
	}

	logPath := getConsoleLogPath(time.Now())
	logDir := filepath.Dir(logPath)

	if err := os.MkdirAll(logDir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		consoleLogMutex.Unlock()
		log.Fatalf( //nolint:gocritic
			"Failed to create console log directory: %v", err) // LINTED: Fatalf
	}

	var err error
	consoleLogFile, err = os.OpenFile(logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(logPerm)) //nolint:gosec
	if err != nil {
		consoleLogMutex.Unlock()
		log.Fatalf(
			"Failed to open console log file: %v", err) // LINTED: Fatalf
	}

	if isConsoleLogQuiet {
		fmt.Fprintf(
			os.Stderr, "%s Console logging enabled (suppressing console output)\n",
			nowStamp())
	} else {
		fmt.Fprintf(
			os.Stderr, "%s Console logging enabled (not suppressing console output)\n",
			nowStamp())
	}

	if isConsoleLogQuiet {
		log.SetOutput(consoleLogFile)
	} else {
		log.SetOutput(io.MultiWriter(os.Stdout, consoleLogFile))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func compressLogFile(logFilePath string) {
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(logFilePath)
	if err != nil {
		log.Printf("Failed to read log %q for compression: %v", logFilePath, err)

		return
	}

	var compressedFilePath string
	var compressedFile *os.File
	var writer io.WriteCloser

	var gzipLevel int

	switch compressLevel {
	case "fast":
		gzipLevel = gzip.BestSpeed

	case "normal":
		gzipLevel = gzip.DefaultCompression

	case "high":
		gzipLevel = gzip.BestCompression
	}

	var zstdLevel zstd.EncoderLevel

	switch compressLevel {
	case "fast":
		zstdLevel = zstd.SpeedFastest

	case "normal":
		zstdLevel = zstd.SpeedDefault

	case "high":
		zstdLevel = zstd.SpeedBestCompression
	}

	switch compressAlgo {
	case "gzip":
		compressedFilePath = logFilePath + ".gz"
		compressedFile, err = os.Create(compressedFilePath)
		if err != nil {
			log.Printf("Failed to create compressed file %q: %v", compressedFilePath, err)

			return
		}

		writer, err = gzip.NewWriterLevel(compressedFile, gzipLevel)
		if err != nil {
			log.Printf("Error creating gzip writer for %q: %v", compressedFilePath, err)
			if err := compressedFile.Close(); err != nil {
				log.Printf("Error closing compressed file after gzip writer error: %v", err)
			}

			return
		}

	case "xz":
		compressedFilePath = logFilePath + ".xz"
		compressedFile, err = os.Create(compressedFilePath)
		if err != nil {
			log.Printf("Failed to create compressed file %q: %v", compressedFilePath, err)

			return
		}

		writer, err = xz.NewWriter(compressedFile)
		if err != nil {
			log.Printf("Error creating xz writer for %q: %v", compressedFilePath, err)
			if err := compressedFile.Close(); err != nil {
				log.Printf("Error closing compressed file after xz writer error: %v", err)
			}

			return
		}

	case "zstd":
		compressedFilePath = logFilePath + ".zst"
		compressedFile, err = os.Create(compressedFilePath)
		if err != nil {
			log.Printf("Failed to create compressed file %q: %v", compressedFilePath, err)

			return
		}

		writer, err = zstd.NewWriter(
			compressedFile, zstd.WithEncoderLevel(zstdLevel))
		if err != nil {
			log.Printf("Error creating zstd writer for %q: %v", compressedFilePath, err)
			if err := compressedFile.Close(); err != nil {
				log.Printf("Error closing compressed file after zstd writer error: %v", err)
			}

			return
		}

	default:
		log.Printf("Unknown compression algorithm: %s", compressAlgo)

		return
	}

	defer func() {
		if err := compressedFile.Close(); err != nil {
			if strings.Contains(err.Error(), "writer already closed") {
				log.Printf("Error closing compressed file: %v", err)
			}
		}
	}()

	defer func() {
		if err := writer.Close(); err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				log.Printf("Error closing writer: %v", err)
			}
		}
	}()

	_, err = writer.Write(data)
	if err != nil {
		log.Printf("Error writing to compressed file %q: %v", compressedFilePath, err)

		return
	}

	err = writer.Close()
	if err != nil {
		log.Printf("Error closing writer for %q: %v", compressedFilePath, err)

		return
	}

	err = compressedFile.Close()
	if err != nil {
		log.Printf("Error closing compressed file %q: %v", compressedFilePath, err)

		return
	}

	err = os.Remove(logFilePath)
	if err != nil {
		log.Printf("Error removing original log %q after compression: %v", logFilePath, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func parseIPListFile(filePath string) ([]*net.IPNet, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Error closing file: %v", err)
		}
	}()

	var networks []*net.IPNet
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err == nil {
			networks = append(networks, ipNet)

			continue
		}

		ip := net.ParseIP(line)
		if ip != nil {
			if ip.To4() != nil {
				networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			} else {
				networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}

			continue
		}

		return nil, fmt.Errorf("BAD IP OR CIDR BLOCK \"%s\" ON LINE %d [%s]",
			line, lineNumber, filePath)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}

	return networks, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listGoroutines() {
	buf := make([]byte, 1<<20)
	stacklen := runtime.Stack(buf, true)
	stackTrace := string(buf[:stacklen])

	goroutinesRaw := strings.Split(stackTrace, "\n\n")

	type GoroutineInfo struct {
		ID         string
		State      string
		Entrypoint string
		Caller     string
	}

	goroutines := make([]GoroutineInfo, 0, len(goroutinesRaw))

	for _, g := range goroutinesRaw {
		if strings.TrimSpace(g) == "" {
			continue
		}

		lines := strings.Split(g, "\n")
		if len(lines) < 2 {
			continue
		}

		header := strings.Fields(lines[0])
		if len(header) < 2 {
			continue
		}

		id := header[1]
		state := strings.Trim(lines[0][len(header[0])+len(id)+2:], " :")

		entrypoint := lines[1]
		caller := ""
		if len(lines) > 2 {
			caller = strings.TrimSpace(lines[2])
		}

		goroutines = append(goroutines, GoroutineInfo{
			ID:         id,
			State:      state,
			Entrypoint: entrypoint,
			Caller:     caller,
		})
	}

	if len(goroutines) == 0 { // Not possible!
		return
	}

	type row struct{ Name, Value string }
	allRows := make([]row, 0, len(goroutines)*4)

	for _, g := range goroutines {
		allRows = append(allRows, row{"Name", "Goroutine #" + g.ID})
		allRows = append(allRows, row{"State", g.State})
		allRows = append(allRows, row{"Entrypoint", g.Entrypoint})
		allRows = append(allRows, row{"Caller", g.Caller})
	}

	maxName := 0
	maxVal := 0

	for _, r := range allRows {
		if len(r.Name) > maxName {
			maxName = len(r.Name)
		}

		if len(r.Value) > maxVal {
			maxVal = len(r.Value)
		}
	}

	border := fmt.Sprintf(
		"+=%s=+=%s=+\n", strings.Repeat("=", maxName), strings.Repeat("=", maxVal),
	)

	fmt.Printf("\r\n")

	fmt.Print(border)

	for _, g := range goroutines {
		fmt.Printf("| %-*s | %-*s |\n", maxName, "Name", maxVal, "Goroutine #"+g.ID)
		fmt.Printf("| %-*s | %-*s |\n", maxName, "State", maxVal, g.State)
		fmt.Printf("| %-*s | %-*s |\n", maxName, "Entrypoint", maxVal, g.Entrypoint)
		fmt.Printf("| %-*s | %-*s |\n", maxName, "Caller", maxVal, g.Caller)

		fmt.Print(border)
	}

	fmt.Printf("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func checkPrivilegedPorts(addrs []string) {
	for _, addr := range addrs {
		_, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)

		if port > 0 && port < 1024 {
			checkCapability()

			return
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
