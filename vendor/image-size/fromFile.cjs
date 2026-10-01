// SPDX-License-Identifier: MIT
'use strict'

const fs = require('fs')
const imageSize = require('./index.cjs')

async function imageSizeFromFile(filePath) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0)
  const handle = await fs.promises.open(filePath, flags)
  try {
    const stat = await handle.stat()
    if (!stat.isFile()) {
      throw new TypeError('Unsupported or unsafe image format: input is not a regular file')
    }
    if (stat.size > imageSize.MAX_INPUT_BYTES) {
      throw new TypeError('Unsupported or unsafe image format: input exceeds 10 MiB')
    }

    // Read at most one byte beyond the limit. This detects growth after fstat
    // without allowing a replaced or expanding path to cause an unbounded read.
    const limit = imageSize.MAX_INPUT_BYTES + 1
    const chunks = []
    let total = 0
    while (total < limit) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, limit - total))
      const {bytesRead} = await handle.read(chunk, 0, chunk.length, total)
      if (bytesRead === 0) break
      chunks.push(chunk.subarray(0, bytesRead))
      total += bytesRead
    }
    if (total > imageSize.MAX_INPUT_BYTES) {
      throw new TypeError('Unsupported or unsafe image format: input exceeds 10 MiB')
    }
    return imageSize(Buffer.concat(chunks, total))
  } finally {
    await handle.close()
  }
}

module.exports = {imageSizeFromFile}
