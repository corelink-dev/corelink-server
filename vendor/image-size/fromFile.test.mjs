import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {mkdtemp, rename, rm, writeFile} from 'node:fs/promises'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {createRequire} from 'node:module'
import {imageSizeFromFile as imageSizeFromFileEsm} from './fromFile.mjs'

const require = createRequire(import.meta.url)
const {imageSizeFromFile: imageSizeFromFileCjs} = require('./fromFile.cjs')
const imageSizeFromFileVariants = [
  ['CommonJS', imageSizeFromFileCjs],
  ['ES module', imageSizeFromFileEsm],
]
const svg = '<svg width="17" height="23"></svg>'

async function withTempDir(run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'image-size-from-file-'))
  try {
    await run(directory)
  } finally {
    await rm(directory, {recursive: true, force: true})
  }
}

for (const [moduleName, imageSizeFromFile] of imageSizeFromFileVariants) {
  test(`${moduleName}: parses ordinary input`, async () => withTempDir(async (directory) => {
    const file = path.join(directory, 'image.svg')
    await writeFile(file, svg)
    assert.deepEqual(await imageSizeFromFile(file), {width: 17, height: 23, type: 'svg'})
  }))

  test(`${moduleName}: rejects an oversized file`, async () => withTempDir(async (directory) => {
    const file = path.join(directory, 'large.svg')
    await writeFile(file, Buffer.alloc(10 * 1024 * 1024 + 1))
    await assert.rejects(imageSizeFromFile(file), /input exceeds 10 MiB/)
  }))

  test(`${moduleName}: rejects a FIFO without blocking`, {timeout: 1500}, async (t) => withTempDir(async (directory) => {
    if (process.platform === 'win32') {
      t.skip('named FIFO creation is unavailable on Windows')
      return
    }
    const fifo = path.join(directory, 'image.pipe')
    try {
      execFileSync('mkfifo', [fifo])
    } catch {
      t.skip('mkfifo is unavailable')
      return
    }
    await assert.rejects(imageSizeFromFile(fifo), /not a regular file/)
  }))

  test(`${moduleName}: reads the opened file after its path is replaced`, async () => withTempDir(async (directory) => {
    const file = path.join(directory, 'image.svg')
    const replacement = path.join(directory, 'replacement.svg')
    await writeFile(file, svg)
    await writeFile(replacement, '<svg width="999" height="999"></svg>')

    const originalOpen = fs.promises.open
    fs.promises.open = async (...args) => {
      const handle = await originalOpen(...args)
      await rename(replacement, file)
      return handle
    }
    try {
      assert.deepEqual(await imageSizeFromFile(file), {width: 17, height: 23, type: 'svg'})
    } finally {
      fs.promises.open = originalOpen
    }
  }))

  test(`${moduleName}: rejects growth beyond the limit after fstat`, async () => withTempDir(async (directory) => {
    const file = path.join(directory, 'growing.svg')
    await writeFile(file, svg)

    const originalOpen = fs.promises.open
    fs.promises.open = async (...args) => {
      const handle = await originalOpen(...args)
      await writeFile(file, Buffer.alloc(10 * 1024 * 1024 + 1))
      return handle
    }
    try {
      await assert.rejects(imageSizeFromFile(file), /input exceeds 10 MiB/)
    } finally {
      fs.promises.open = originalOpen
    }
  }))
}
