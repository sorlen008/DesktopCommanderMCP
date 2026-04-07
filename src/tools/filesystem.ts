import fs from "fs/promises";
import path from "path";
import os from 'os';
import fetch from 'cross-fetch';
import { capture } from '../utils/capture.js';
import { withTimeout } from '../utils/withTimeout.js';
import { configManager } from '../config-manager.js';
import { getFileHandler, TextFileHandler } from '../utils/files/index.js';
import type { ReadOptions, FileResult, PdfPageItem } from '../utils/files/base.js';
import { isPdfFile } from "./mime-types.js";
import { parsePdfToMarkdown, editPdf, PdfOperations, PdfMetadata, parseMarkdownToPdf } from './pdf/index.js';
import { isBinaryFile } from 'isbinaryfile';

// CONSTANTS SECTION
const FILE_OPERATION_TIMEOUTS = {
    PATH_VALIDATION: 10000,
    URL_FETCH: 30000,
    FILE_READ: 30000,
} as const;

const FILE_SIZE_LIMITS = {
    LINE_COUNT_LIMIT: 10 * 1024 * 1024,
} as const;

async function getMimeTypeInfo(filePath: string): Promise<{ mimeType: string; isImage: boolean; isPdf: boolean }> {
    const { getMimeType, isImageFile, isPdfFile } = await import('./mime-types.js');
    const mimeType = getMimeType(filePath);
    const isImage = isImageFile(mimeType);
    const isPdf = isPdfFile(mimeType);
    return { mimeType, isImage, isPdf };
}

function getFileExtension(filePath: string): string {
    return path.extname(filePath).toLowerCase();
}

async function getDefaultReadLength(): Promise<number> {
    const config = await configManager.getConfig();
    return config.fileReadLineLimit ?? 1000;
}

async function getAllowedDirs(): Promise<string[]> {
    try {
        let allowedDirectories;
        const config = await configManager.getConfig();
        if (config.allowedDirectories && Array.isArray(config.allowedDirectories)) {
            allowedDirectories = config.allowedDirectories;
        } else {
            allowedDirectories = [
                os.homedir()
            ];
            await configManager.setValue('allowedDirectories', allowedDirectories);
        }
        return allowedDirectories;
    } catch (error) {
        console.error('Failed to initialize allowed directories:', error);
        // Fail-closed: if the config cannot be read (e.g., corrupted JSON), restrict access to
        // the home directory only. Returning [] is interpreted as "allow all paths" by
        // isPathAllowed(), enabling a sandbox-escape attack where an adversary corrupts
        // config.json then restarts the server to gain unrestricted filesystem access.
        // See: https://github.com/wonderwhy-er/DesktopCommanderMCP/issues/419
        return [os.homedir()];
    }
}

function normalizePath(p: string): string {
    return path.normalize(expandHome(p)).toLowerCase();
}

function expandHome(filepath: string): string {
    if (filepath.startsWith('~/') || filepath === '~') {
        return path.join(os.homedir(), filepath.slice(1));
    }
    return filepath;
}

async function validateParentDirectories(directoryPath: string): Promise<boolean> {
    const parentDir = path.dirname(directoryPath);
    if (parentDir === directoryPath || parentDir === path.dirname(parentDir)) {
        return false;
    }
    try {
        await fs.realpath(parentDir);
        return true;
    } catch {
        return validateParentDirectories(parentDir);
    }
}

async function isPathAllowed(pathToCheck: string): Promise<boolean> {
    const allowedDirectories = await getAllowedDirs();
    if (allowedDirectories.includes('/') || allowedDirectories.length === 0) {
        return true;
    }
    let normalizedPathToCheck = normalizePath(pathToCheck);
    if (normalizedPathToCheck.slice(-1) === path.sep) {
        normalizedPathToCheck = normalizedPathToCheck.slice(0, -1);
    }
    const isAllowed = allowedDirectories.some(allowedDir => {
        let normalizedAllowedDir = normalizePath(allowedDir);
        if (normalizedAllowedDir.slice(-1) === path.sep) {
            normalizedAllowedDir = normalizedAllowedDir.slice(0, -1);
        }
        if (normalizedPathToCheck === normalizedAllowedDir) {
            return true;
        }
        const subdirCheck = normalizedPathToCheck.startsWith(normalizedAllowedDir + path.sep);
        if (subdirCheck) {
            return true;
        }
        if (normalizedAllowedDir === 'c:' && process.platform === 'win32') {
            return normalizedPathToCheck.startsWith('c:');
        }
        return false;
    });
    return isAllowed;
}

export async function validatePath(requestedPath: string): Promise<string> {
    const validationOperation = async (): Promise<string> => {
        const expandedPath = expandHome(requestedPath);
        const absoluteOriginal = path.isAbsolute(expandedPath)
            ? path.resolve(expandedPath)
            : path.resolve(process.cwd(), expandedPath);
        let resolvedRealPath: string | null = null;
        try {
            resolvedRealPath = await fs.realpath(absoluteOriginal, { encoding: 'utf8' });
        } catch (error) {
            const err = error as NodeJS.ErrnoException;
            if (!err.code || err.code !== 'ENOENT') {
                capture('server_path_realpath_error', { error: err.message, path: absoluteOriginal });
                throw new Error(`Failed to resolve symlink for path: ${absoluteOriginal}. Error: ${err.message}`);
            }
        }
        const pathForNextCheck = resolvedRealPath ?? absoluteOriginal;
        if (!(await isPathAllowed(pathForNextCheck))) {
            capture('server_path_validation_error', { error: 'Path not allowed', allowedDirsCount: (await getAllowedDirs()).length });
            throw new Error(`Path not allowed: ${requestedPath}. Must be within one of these directories: ${(await getAllowedDirs()).join(', ')}`);
        }
        try {
            const stats = await fs.stat(absoluteOriginal);
            if (resolvedRealPath) {
                return resolvedRealPath;
            }
            return absoluteOriginal;
        } catch (error) {
            if (await validateParentDirectories(absoluteOriginal)) {
                return absoluteOriginal;
            }
            return absoluteOriginal;
        }
    };
    const result = await withTimeout(
        validationOperation(),
        FILE_OPERATION_TIMEOUTS.PATH_VALIDATION,
        `Path validation operation`,
        null
    );
    if (result === null) {
        capture('server_path_validation_timeout', { timeoutMs: FILE_OPERATION_TIMEOUTS.PATH_VALIDATION });
        throw new Error(`Path validation failed for path: ${requestedPath}`);
    }
    return result;
}

export type { FileResult } from '../utils/files/base.js';

type PdfPayload = {
    metadata: PdfMetadata;
    pages: PdfPageItem[];
}

type FileResultPayloads = PdfPayload;

export async function readFileFromUrl(url: string): Promise<FileResult> {
    const { isImageFile } = await import('./mime-types.js');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FILE_OPERATION_TIMEOUTS.URL_FETCH);
    try {
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const contentType = response.headers.get('content-type') || 'text/plain';
        const isImage = isImageFile(contentType);
        const isPdf = isPdfFile(contentType) || url.toLowerCase().endsWith('.pdf');
        if (isPdf) {
            const pdfResult = await parsePdfToMarkdown(url);
            return {
                content: "",
                mimeType: 'text/plain',
                metadata: {
                    isImage: false,
                    isPdf: true,
                    author: pdfResult.metadata.author,
                    title: pdfResult.metadata.title,
                    totalPages: pdfResult.metadata.totalPages,
                    pages: pdfResult.pages
                }
            };
        } else if (isImage) {
            const buffer = await response.arrayBuffer();
            const content = Buffer.from(buffer).toString('base64');
            return { content, mimeType: contentType, metadata: { isImage } };
        } else {
            const content = await response.text();
            return { content, mimeType: contentType, metadata: { isImage } };
        }
    } catch (error) {
        clearTimeout(timeoutId);
        const errorMessage = error instanceof DOMException && error.name === 'AbortError'
            ? `URL fetch timed out after ${FILE_OPERATION_TIMEOUTS.URL_FETCH}ms: ${url}`
            : `Failed to fetch URL: ${error instanceof Error ? error.message : String(error)}`;
        throw new Error(errorMessage);
    }
}

export async function readFileFromDisk(
    filePath: string,
    options?: ReadOptions
): Promise<FileResult> {
    const { offset = 0, sheet, range } = options ?? {};
    let { length } = options ?? {};
    if (!filePath || typeof filePath !== 'string') {
        throw new Error('Invalid file path provided');
    }
    if (length === undefined) {
        length = await getDefaultReadLength();
    }
    const validPath = await validatePath(filePath);
    const fileExtension = getFileExtension(validPath);
    try {
        const stats = await fs.stat(validPath);
        if (stats.isDirectory()) {
            const dirListOp = async () => {
                const entries = await listDirectory(validPath);
                const listing = entries.join('\n');
                return {
                    content: `This is a directory, not a file. Use the list_directory tool instead of read_file for directories.\n\n${listing}`,
                    mimeType: 'text/plain',
                    metadata: { isImage: false, isDirectory: true }
                } as FileResult;
            };
            const dirResult = await withTimeout(dirListOp(), FILE_OPERATION_TIMEOUTS.FILE_READ, 'Directory listing fallback', null);
            if (dirResult === null) {
                throw new Error(`Directory listing timed out for: ${filePath}`);
            }
            return dirResult;
        }
    } catch (error) {
        const err = error as NodeJS.ErrnoException;
        if (err.message?.includes('Directory listing') || err.message?.includes('list_directory')) {
            throw error;
        }
    }
    try {
        const stats = await fs.stat(validPath);
        capture('server_read_file', { fileExtension: fileExtension, offset: offset, length: length, fileSize: stats.size });
    } catch (error) {
        console.error('error catch ' + error);
        const errorMessage = error instanceof Error ? error.message : String(error);
        capture('server_read_file_error', { error: errorMessage, fileExtension: fileExtension });
    }
    const readOperation = async () => {
        const handler = await getFileHandler(validPath);
        const result = await handler.read(validPath, { offset, length, sheet, range, includeStatusMessage: true });
        let content: string;
        if (typeof result.content === 'string') {
            content = result.content;
        } else if (result.metadata?.isImage) {
            content = result.content.toString('base64');
        } else {
            content = result.content.toString('utf8');
        }
        return { content, mimeType: result.mimeType, metadata: result.metadata };
    };
    const result = await withTimeout(readOperation(), FILE_OPERATION_TIMEOUTS.FILE_READ, `Read file operation for ${filePath}`, null);
    if (result == null) {
        throw new Error('Failed to read the file');
    }
    return result;
}

export async function readFile(filePath: string, options?: ReadOptions): Promise<FileResult> {
    const { isUrl, offset, length, sheet, range } = options ?? {};
    return isUrl ? readFileFromUrl(filePath) : readFileFromDisk(filePath, { offset, length, sheet, range });
}

export async function readFileInternal(filePath: string, offset: number = 0, length?: number): Promise<string> {
    if (length === undefined) {
        length = await getDefaultReadLength();
    }
    const validPath = await validatePath(filePath);
    const fileExtension = getFileExtension(validPath);
    const { mimeType, isImage } = await getMimeTypeInfo(validPath);
    if (isImage) {
        throw new Error('Cannot read image files as text for internal operations');
    }
    const content = await fs.readFile(validPath, 'utf8');
    if (offset === 0 && length >= Number.MAX_SAFE_INTEGER) {
        return content;
    }
    const lines = TextFileHandler.splitLinesPreservingEndings(content);
    const selectedLines = lines.slice(offset, offset + length);
    return selectedLines.join('');
}

export async function writeFile(filePath: string, content: string, mode: 'rewrite' | 'append' = 'rewrite'): Promise<void> {
    const validPath = await validatePath(filePath);
    const fileExtension = getFileExtension(validPath);
    const contentBytes = Buffer.from(content).length;
    const lineCount = TextFileHandler.countLines(content);
    capture('server_write_file', { fileExtension: fileExtension, mode: mode, contentBytes: contentBytes, lineCount: lineCount });
    const handler = await getFileHandler(validPath);
    await handler.write(validPath, content, mode);
}

export interface MultiFileResult {
    path: string;
    content?: string;
    mimeType?: string;
    isImage?: boolean;
    error?: string;
    isPdf?: boolean;
    payload?: FileResultPayloads;
}

export async function readMultipleFiles(paths: string[]): Promise<MultiFileResult[]> {
    return Promise.all(
        paths.map(async (filePath: string) => {
            try {
                const validPath = await validatePath(filePath);
                const fileResult = await readFile(validPath);
                let content: string;
                if (typeof fileResult.content === 'string') {
                    content = fileResult.content;
                } else if (fileResult.metadata?.isImage) {
                    content = fileResult.content.toString('base64');
                } else {
                    content = fileResult.content.toString('utf8');
                }
                return {
                    path: filePath,
                    content,
                    mimeType: fileResult.mimeType,
                    isImage: fileResult.metadata?.isImage ?? false,
                    isPdf: fileResult.metadata?.isPdf ?? false,
                    payload: fileResult.metadata?.isPdf ? {
                        metadata: { author: fileResult.metadata.author, title: fileResult.metadata.title, totalPages: fileResult.metadata.totalPages ?? 0 },
                        pages: fileResult.metadata.pages ?? []
                    } : undefined
                };
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                return { path: filePath, error: errorMessage };
            }
        }),
    );
}

export async function createDirectory(dirPath: string): Promise<void> {
    const validPath = await validatePath(dirPath);
    await fs.mkdir(validPath, { recursive: true });
}

export async function listDirectory(dirPath: string, depth: number = 2): Promise<string[]> {
    const validPath = await validatePath(dirPath);
    const results: string[] = [];
    const MAX_NESTED_ITEMS = 100;
    async function listRecursive(currentPath: string, currentDepth: number, relativePath: string = '', isTopLevel: boolean = true): Promise<void> {
        if (currentDepth <= 0) return;
        let entries;
        try {
            entries = await fs.readdir(currentPath, { withFileTypes: true });
        } catch (error) {
            const displayPath = relativePath || path.basename(currentPath);
            results.push(`[DENIED] ${displayPath}`);
            return;
        }
        const totalEntries = entries.length;
        let entriesToShow = entries;
        let filteredCount = 0;
        if (!isTopLevel && totalEntries > MAX_NESTED_ITEMS) {
            entriesToShow = entries.slice(0, MAX_NESTED_ITEMS);
            filteredCount = totalEntries - MAX_NESTED_ITEMS;
        }
        for (const entry of entriesToShow) {
            const fullPath = path.join(currentPath, entry.name);
            const displayPath = relativePath ? path.join(relativePath, entry.name) : entry.name;
            results.push(`${entry.isDirectory() ? "[DIR]" : "[FILE]"} ${displayPath}`);
            if (entry.isDirectory() && currentDepth > 1) {
                try {
                    await validatePath(fullPath);
                    await listRecursive(fullPath, currentDepth - 1, displayPath, false);
                } catch (error) {
                    continue;
                }
            }
        }
        if (filteredCount > 0) {
            const displayPath = relativePath || path.basename(currentPath);
            results.push(`[WARNING] ${displayPath}: ${filteredCount} items hidden (showing first ${MAX_NESTED_ITEMS} of ${totalEntries} total)`);
        }
    }
    await listRecursive(validPath, depth, '', true);
    return results;
}

export async function moveFile(sourcePath: string, destinationPath: string): Promise<void> {
    const validSourcePath = await validatePath(sourcePath);
    const validDestPath = await validatePath(destinationPath);
    await fs.rename(validSourcePath, validDestPath);
}

export async function searchFiles(rootPath: string, pattern: string): Promise<string[]> {
    const { searchManager } = await import('../search-manager.js');
    try {
        const result = await searchManager.startSearch({
            rootPath, pattern, searchType: 'files', ignoreCase: true, maxResults: 5000, earlyTermination: true,
        });
        const sessionId = result.sessionId;
        let allResults: string[] = [];
        let isComplete = result.isComplete;
        let startTime = Date.now();
        for (const searchResult of result.results) {
            if (searchResult.type === 'file') { allResults.push(searchResult.file); }
        }
        while (!isComplete) {
            await new Promise(resolve => setTimeout(resolve, 100));
            const results = searchManager.readSearchResults(sessionId);
            isComplete = results.isComplete;
            for (const searchResult of results.results) {
                if (searchResult.file !== '__LAST_READ_MARKER__' && searchResult.type === 'file') {
                    allResults.push(searchResult.file);
                }
            }
            if (Date.now() - startTime > 30000) {
                searchManager.terminateSearch(sessionId);
                break;
            }
        }
        capture('server_search_files_complete', { resultsCount: allResults.length, patternLength: pattern.length, usedRipgrep: true });
        return allResults;
    } catch (error) {
        capture('server_search_files_ripgrep_fallback', { error: error instanceof Error ? error.message : 'Unknown error' });
        return await searchFilesNodeJS(rootPath, pattern);
    }
}

async function searchFilesNodeJS(rootPath: string, pattern: string): Promise<string[]> {
    const results: string[] = [];
    async function search(currentPath: string): Promise<void> {
        let entries;
        try {
            entries = await fs.readdir(currentPath, { withFileTypes: true });
        } catch (error) {
            return;
        }
        for (const entry of entries) {
            const fullPath = path.join(currentPath, entry.name);
            try {
                await validatePath(fullPath);
                if (entry.name.toLowerCase().includes(pattern.toLowerCase())) {
                    results.push(fullPath);
                }
                if (entry.isDirectory()) {
                    await search(fullPath);
                }
            } catch (error) {
                continue;
            }
        }
    }
    try {
        const validPath = await validatePath(rootPath);
        await search(validPath);
        capture('server_search_files_complete', { resultsCount: results.length, patternLength: pattern.length, usedRipgrep: false });
        return results;
    } catch (error) {
        capture('server_search_files_error', { errorType: error instanceof Error ? error.name : 'Unknown', error: 'Error with root path', isRootPathError: true });
        throw error;
    }
}

export async function getFileInfo(filePath: string): Promise<Record<string, any>> {
    const validPath = await validatePath(filePath);
    const stats = await fs.stat(validPath);
    const fallbackInfo = {
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        accessed: stats.atime,
        isDirectory: stats.isDirectory(),
        isFile: stats.isFile(),
        permissions: stats.mode.toString(8).slice(-3),
        fileType: 'text' as const,
        metadata: undefined as Record<string, any> | undefined,
    };
    const handler = await getFileHandler(validPath);
    let fileInfo;
    try {
        fileInfo = await handler.getInfo(validPath);
    } catch (error) {
        fileInfo = fallbackInfo;
    }
    const info: Record<string, any> = {
        size: fileInfo.size ?? fallbackInfo.size,
        created: fileInfo.created ?? fallbackInfo.created,
        modified: fileInfo.modified ?? fallbackInfo.modified,
        accessed: fileInfo.accessed ?? fallbackInfo.accessed,
        isDirectory: fileInfo.isDirectory ?? fallbackInfo.isDirectory,
        isFile: fileInfo.isFile ?? fallbackInfo.isFile,
        permissions: fileInfo.permissions ?? fallbackInfo.permissions,
        fileType: fileInfo.fileType ?? fallbackInfo.fileType,
    };
    if (fileInfo.metadata) {
        if (fileInfo.metadata.lineCount !== undefined) {
            info.lineCount = fileInfo.metadata.lineCount;
            info.lastLine = fileInfo.metadata.lineCount - 1;
            info.appendPosition = fileInfo.metadata.lineCount;
        }
        if (fileInfo.metadata.sheets) {
            info.sheets = fileInfo.metadata.sheets;
            info.isExcelFile = true;
        }
        if (fileInfo.metadata.isImage) { info.isImage = true; }
        if (fileInfo.metadata.isPdf) {
            info.isPdf = true;
            info.totalPages = fileInfo.metadata.totalPages;
            if (fileInfo.metadata.title) info.title = fileInfo.metadata.title;
            if (fileInfo.metadata.author) info.author = fileInfo.metadata.author;
        }
        if (fileInfo.metadata.isBinary) { info.isBinary = true; }
    }
    return info;
}

export async function writePdf(
    filePath: string,
    content: string | PdfOperations[],
    outputPath?: string,
    options: any = {}
): Promise<void> {
    const validPath = await validatePath(filePath);
    const fileExtension = getFileExtension(validPath);
    if (typeof content === 'string') {
        capture('server_write_pdf', { fileExtension: fileExtension, contentLength: content.length, mode: 'create' });
        const pdfBuffer = await parseMarkdownToPdf(content, options);
        const targetPath = outputPath ? await validatePath(outputPath) : validPath;
        await fs.writeFile(targetPath, pdfBuffer);
    } else if (Array.isArray(content)) {
        const targetPath = outputPath ? await validatePath(outputPath) : validPath;
        const operations: PdfOperations[] = [];
        for (const o of content) {
            if (o.type === 'insert') {
                if (o.sourcePdfPath) {
                    o.sourcePdfPath = await validatePath(o.sourcePdfPath);
                }
            }
            operations.push(o);
        }
        capture('server_write_pdf', { fileExtension: fileExtension, operationCount: operations.length, mode: 'modify', deleteCount: operations.filter(op => op.type === 'delete').length, insertCount: operations.filter(op => op.type === 'insert').length });
        const modifiedPdfBuffer = await editPdf(validPath, operations);
        await fs.writeFile(targetPath, modifiedPdfBuffer);
    } else {
        throw new Error('Invalid content type for writePdf. Expected string (markdown) or array of operations.');
    }
}