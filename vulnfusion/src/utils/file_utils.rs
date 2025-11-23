// 中文说明：
// 文件/工程工具：递归发现 Rust 文件、并行过滤、读取内容/行数、工程根定位与
// 输出目录/文件写入等能力，服务于分析入口与报告生成。
use std::fs;
use std::path::{Path, PathBuf};
use std::io::{self, Read};
use walkdir::WalkDir;
use rayon::prelude::*;

use crate::utils::constants::*;
use crate::utils::error::FileError;

pub fn find_rust_files<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>, FileError> {
    let mut rust_files = Vec::new();
    
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "rs" {
                    rust_files.push(path.to_path_buf());
                }
            }
        }
    }
    
    Ok(rust_files)
}

pub fn find_rust_files_parallel<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>, FileError> {
    let entries: Vec<_> = WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();
    
    let rust_files: Vec<PathBuf> = entries
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "rs" {
                        return Some(path.to_path_buf());
                    }
                }
            }
            None
        })
        .collect();
    
    Ok(rust_files)
}

pub fn read_file_content<P: AsRef<Path>>(path: P) -> Result<String, FileError> {
    let path = path.as_ref();
    
    // Check file size
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_FILE_SIZE as u64 {
        return Err(FileError::FileTooLarge(path.to_path_buf()));
    }
    
    let mut file = fs::File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    
    Ok(content)
}

pub fn read_file_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>, FileError> {
    let content = read_file_content(path)?;
    Ok(content.lines().map(|s| s.to_string()).collect())
}

pub fn is_rust_project<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();
    RUST_PROJECT_FILES.iter().any(|&file| path.join(file).exists())
}

pub fn find_project_root<P: AsRef<Path>>(path: P) -> Option<PathBuf> {
    let mut current = path.as_ref().to_path_buf();
    
    loop {
        if is_rust_project(&current) {
            return Some(current);
        }
        
        if !current.pop() {
            break;
        }
    }
    
    None
}

pub fn get_file_size<P: AsRef<Path>>(path: P) -> Result<u64, FileError> {
    let metadata = fs::metadata(path)?;
    Ok(metadata.len())
}

pub fn get_file_lines<P: AsRef<Path>>(path: P) -> Result<usize, FileError> {
    let content = read_file_content(path)?;
    Ok(content.lines().count())
}

pub fn is_binary_file<P: AsRef<Path>>(path: P) -> Result<bool, FileError> {
    let content = read_file_content(path)?;
    Ok(content.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t'))
}

pub fn filter_files_by_size<P: AsRef<Path>>(
    files: Vec<PathBuf>,
    max_size: usize,
) -> Vec<PathBuf> {
    files
        .into_par_iter()
        .filter_map(|file| {
            match get_file_size(&file) {
                Ok(size) if size <= max_size as u64 => Some(file),
                _ => None,
            }
        })
        .collect()
}

pub fn get_relative_path<P: AsRef<Path>, Q: AsRef<Path>>(
    base: P,
    target: Q,
) -> Result<PathBuf, FileError> {
    let base = base.as_ref();
    let target = target.as_ref();
    
    target.strip_prefix(base)
        .map(|p| p.to_path_buf())
        .map_err(|_| FileError::PathError(format!("Cannot make {} relative to {}", 
            target.display(), base.display())))
}

pub fn create_output_directory<P: AsRef<Path>>(path: P) -> Result<(), FileError> {
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn write_to_file<P: AsRef<Path>>(path: P, content: &str) -> Result<(), FileError> {
    fs::write(path, content)?;
    Ok(())
}

pub fn append_to_file<P: AsRef<Path>>(path: P, content: &str) -> Result<(), FileError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    
    writeln!(file, "{}", content)?;
    Ok(())
}

pub fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists()
}

pub fn is_directory<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().is_dir()
}

pub fn get_directory_size<P: AsRef<Path>>(path: P) -> Result<u64, FileError> {
    let mut total_size = 0u64;
    
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total_size += metadata.len();
            }
        }
    }
    
    Ok(total_size)
}

pub fn count_lines_of_code<P: AsRef<Path>>(path: P) -> Result<usize, FileError> {
    let rust_files = find_rust_files(path)?;
    
    let total_lines: usize = rust_files
        .par_iter()
        .filter_map(|file| get_file_lines(file).ok())
        .sum();
    
    Ok(total_lines)
}

pub fn find_cargo_toml_files<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>, FileError> {
    let mut cargo_files = Vec::new();
    
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() && path.file_name() == Some(std::ffi::OsStr::new("Cargo.toml")) {
            cargo_files.push(path.to_path_buf());
        }
    }
    
    Ok(cargo_files)
}

pub fn get_crate_name_from_cargo_toml<P: AsRef<Path>>(path: P) -> Result<String, FileError> {
    let content = read_file_content(path)?;
    
    // Simple parsing - in production, use toml crate
    for line in content.lines() {
        if line.trim().starts_with("name") && line.contains('=') {
            if let Some(name_part) = line.split('=').nth(1) {
                let name = name_part.trim().trim_matches('"').trim_matches('\'');
                return Ok(name.to_string());
            }
        }
    }
    
    Err(FileError::ParseError("Could not find crate name in Cargo.toml".to_string()))
}