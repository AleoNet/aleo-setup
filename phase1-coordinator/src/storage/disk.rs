use crate::{
    environment::Environment,
    objects::{ContributionFileSignature, Round},
    storage::{Locator, Object, ObjectReader, ObjectWriter, Storage, StorageLocator, StorageObject},
    CoordinatorError,
    CoordinatorState,
};

use itertools::Itertools;
use memmap::{MmapMut, MmapOptions};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
};

#[derive(Debug)]
pub struct Disk {
    environment: Environment,
    manifest: Arc<RwLock<DiskManifest>>,
    open: HashMap<Locator, Arc<RwLock<MmapMut>>>,
    resolver: DiskResolver,
}

impl Storage for Disk {
    /// Loads a new instance of `Disk`.
    #[inline]
    fn load(environment: &Environment) -> Result<Self, CoordinatorError>
    where
        Self: Sized,
    {
        trace!("Loading disk storage");

        // Create a new `Storage` instance, and set the `Environment` and `DiskManifest`.
        let mut storage = Self {
            environment: environment.clone(),
            manifest: Arc::new(RwLock::new(DiskManifest::load(environment.local_base_directory())?)),
            open: HashMap::default(),
            resolver: DiskResolver::new(environment.local_base_directory()),
        };

        // Open the previously opened locators in the manifest.
        {
            // Acquire the manifest file read lock.
            let manifest = storage.manifest.read().unwrap();

            // Open the previously opened locators in the manifest.
            for locator in &manifest.open {
                // Fetch the locator path.
                let path = storage.to_path(&locator)?;

                trace!("Loading {}", path);

                // Fetch the locator file.
                let file = manifest.reopen_file(locator)?;

                // Load the file into memory.
                let memory = unsafe { MmapOptions::new().map_mut(&file)? };

                // Add the object to the set of opened locators.
                storage.open.insert(locator.clone(), Arc::new(RwLock::new(memory)));
            }
        }

        // Create the coordinator state locator if it does not exist yet.
        if !storage.exists(&Locator::CoordinatorState) {
            storage.insert(
                Locator::CoordinatorState,
                Object::CoordinatorState(CoordinatorState::new(environment.clone())),
            )?;
        }

        trace!("Loaded disk storage");
        Ok(storage)
    }

    /// Initializes the location corresponding to the given locator.
    #[inline]
    fn initialize(&mut self, locator: Locator, size: u64) -> Result<(), CoordinatorError> {
        trace!("Initializing {}", self.to_path(&locator)?);

        // Check that the locator does not already exist in storage.
        if self.exists(&locator) {
            error!("Locator in call to initialize() already exists in storage.");
            return Err(CoordinatorError::StorageLocatorAlreadyExists);
        }

        // Acquire the manifest file write lock.
        let mut manifest = self.manifest.write().unwrap();

        // Create the new file.
        let file = manifest.create_file(&locator, Some(size))?;

        // Add the file to the locators.
        self.open.insert(
            locator.clone(),
            Arc::new(RwLock::new(unsafe { MmapOptions::new().map_mut(&file)? })),
        );

        // Save the manifest update to disk.
        manifest.save()?;

        trace!("Initialized {}", self.to_path(&locator)?);
        Ok(())
    }

    /// Returns `true` if a given locator exists in storage. Otherwise, returns `false`.
    #[inline]
    fn exists(&self, locator: &Locator) -> bool {
        let is_in_manifest = self.manifest.read().unwrap().contains(locator);
        #[cfg(test)]
        trace!("Checking if locator exists in storage (manifest = {})", is_in_manifest,);
        is_in_manifest
    }

    /// Returns `true` if a given locator is opened in storage. Otherwise, returns `false`.
    #[inline]
    fn is_open(&self, locator: &Locator) -> bool {
        let is_in_manifest = self.manifest.read().unwrap().contains(locator);
        let is_in_locators = self.open.contains_key(locator);
        #[cfg(test)]
        trace!(
            "Checking if locator file is opened in storage (manifest = {}, locators = {})",
            is_in_manifest,
            is_in_locators
        );
        is_in_manifest && is_in_locators
    }

    /// Returns a copy of an object at the given locator in storage, if it exists.
    #[inline]
    fn get(&self, locator: &Locator) -> Result<Object, CoordinatorError> {
        trace!("Fetching {}", self.to_path(locator)?);

        // Check that the given locator exists in storage.
        if !self.exists(locator) {
            error!("Locator missing in call to get() in storage.");
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Check that the given locator is opened in storage.
        if !self.is_open(locator) {
            error!("Locator in call to get() is not opened in storage.");
            return Err(CoordinatorError::StorageLocatorNotOpen);
        }

        // Acquire the file read lock.
        let reader = self
            .open
            .get(locator)
            .ok_or(CoordinatorError::StorageLockFailed)?
            .read()
            .unwrap();

        let object = match locator {
            Locator::CoordinatorState => {
                let coordinator_state: CoordinatorState = serde_json::from_slice(&*reader)?;
                Ok(Object::CoordinatorState(coordinator_state))
            }
            Locator::RoundHeight => {
                let round_height: u64 = serde_json::from_slice(&*reader)?;
                Ok(Object::RoundHeight(round_height))
            }
            Locator::RoundState(_) => {
                let round: Round = serde_json::from_slice(&*reader)?;
                Ok(Object::RoundState(round))
            }
            Locator::RoundFile(round_height) => {
                // Check that the round size is correct.
                let expected = Object::round_file_size(&self.environment);
                let found = self.size(&locator)?;
                debug!("Round {} filesize is {}", round_height, found);
                if found == 0 || expected != found {
                    error!("Round file size should be {} but found {}", expected, found);
                    return Err(CoordinatorError::RoundFileSizeMismatch.into());
                }

                let mut round_file: Vec<u8> = Vec::with_capacity(expected as usize);
                round_file.write_all(&*reader)?;
                Ok(Object::RoundFile(round_file))
            }
            Locator::ContributionFile(round_height, chunk_id, _, verified) => {
                // Check that the contribution size is correct.
                let expected = Object::contribution_file_size(&self.environment, *chunk_id, *verified);
                let found = self.size(&locator)?;
                debug!("Round {} chunk {} filesize is {}", round_height, chunk_id, found);
                if found == 0 || expected != found {
                    error!("Contribution file size should be {} but found {}", expected, found);
                    return Err(CoordinatorError::ContributionFileSizeMismatch.into());
                }

                let mut contribution_file: Vec<u8> = Vec::with_capacity(expected as usize);
                contribution_file.write_all(&*reader)?;
                Ok(Object::ContributionFile(contribution_file))
            }
            Locator::ContributionFileSignature(round_height, chunk_id, contribution_id, verified) => {
                // Check that the contribution file signature size is correct.
                let expected = Object::contribution_file_signature_size(*verified);
                let found = self.size(&locator)?;
                debug!(
                    "Round {} chunk {} contribution {} signature filesize is {}",
                    round_height, chunk_id, contribution_id, found
                );
                if found == 0 || expected != found {
                    error!(
                        "Contribution signature file size should be {} but found {}",
                        expected, found
                    );
                    return Err(CoordinatorError::ContributionSignatureFileSizeMismatch.into());
                }

                let contribution_file_signature: ContributionFileSignature = serde_json::from_slice(&*reader)?;
                Ok(Object::ContributionFileSignature(contribution_file_signature))
            }
        };

        trace!("Fetched {}", self.to_path(locator)?);
        object
    }

    /// Inserts a new object at the given locator into storage, if it does not exist.
    #[inline]
    fn insert(&mut self, locator: Locator, object: Object) -> Result<(), CoordinatorError> {
        trace!("Inserting {}", self.to_path(&locator)?);

        // Check that the given locator does not exist in storage.
        if self.exists(&locator) {
            error!("Locator in call to insert() already exists in storage.");
            return Err(CoordinatorError::StorageLocatorAlreadyExists);
        }

        // Check that the given locator is not opened in storage.
        if self.is_open(&locator) {
            error!("Locator in call to insert() is opened in storage.");
            return Err(CoordinatorError::StorageLocatorAlreadyExistsAndOpen);
        }

        // Initialize the new file with the object size.
        self.initialize(locator.clone(), object.size())?;

        // Insert the object at the given locator.
        self.update(&locator, object)?;

        trace!("Inserted {}", self.to_path(&locator)?);
        Ok(())
    }

    /// Updates an existing object for the given locator in storage, if it exists.
    #[inline]
    fn update(&mut self, locator: &Locator, object: Object) -> Result<(), CoordinatorError> {
        trace!("Updating {}", self.to_path(locator)?);

        // Check that the given locator exists in storage.
        if !self.exists(locator) {
            error!("Locator missing in call to update() in storage.");
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Check that the given locator is opened in storage.
        if !self.is_open(locator) {
            error!("Locator in call to update() is not opened in storage.");
            return Err(CoordinatorError::StorageLocatorNotOpen);
        }

        // Acquire the file write lock.
        let mut writer = self
            .open
            .get(locator)
            .ok_or(CoordinatorError::StorageLockFailed)?
            .write()
            .unwrap();

        // Acquire the manifest file write lock.
        let mut manifest = self.manifest.write().unwrap();

        // Resize the file to the given object size.
        let file = manifest.resize_file(&locator, object.size())?;

        // Update the writer.
        *writer = unsafe { MmapOptions::new().map_mut(&file)? };

        // Write the new object to the file.
        (*writer).as_mut().write_all(&object.to_bytes())?;

        // Sync all in-memory data to disk.
        writer.flush()?;

        trace!("Updated {}", self.to_path(&locator)?);
        Ok(())
    }

    /// Copies an object from the given source locator to the given destination locator.
    #[inline]
    fn copy(&mut self, source_locator: &Locator, destination_locator: &Locator) -> Result<(), CoordinatorError> {
        trace!(
            "Copying from A to B\n\n\tA: {}\n\tB: {}\n",
            self.to_path(source_locator)?,
            self.to_path(destination_locator)?
        );

        // Check that the given source locator exists in storage.
        if !self.exists(source_locator) {
            error!("Source locator missing in call to copy() in storage.");
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Check that the given destination locator does NOT exist in storage.
        if self.exists(destination_locator) {
            error!("Destination locator in call to copy() already exists in storage.");
            return Err(CoordinatorError::StorageLocatorAlreadyExists);
        }

        // Fetch the source object.
        let source_object = self.get(source_locator)?;

        // Initialize the destination file with the source object size.
        self.initialize(destination_locator.clone(), source_object.size())?;

        // Update the destination locator with the copied source object.
        self.update(destination_locator, source_object)?;

        trace!("Copied to {}", self.to_path(destination_locator)?);
        Ok(())
    }

    /// Removes the object corresponding to the given locator from storage.
    #[inline]
    fn remove(&mut self, locator: &Locator) -> Result<(), CoordinatorError> {
        trace!("Removing {}", self.to_path(locator)?);

        // Check that the locator exists in storage.
        if !self.exists(&locator) {
            error!("Locator in call to remove() doesn't exist in storage.");
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Acquire the manifest file write lock.
        let mut manifest = self.manifest.write().unwrap();

        // Acquire the file write lock.
        let file = self
            .open
            .get(locator)
            .ok_or(CoordinatorError::StorageLockFailed)?
            .write()
            .unwrap();

        // Remove the locator from the manifest.
        manifest.remove_file(locator)?;

        // Remove the file write lock.
        drop(file);

        // Remove the locator from the locators.
        self.open.remove(locator);

        trace!("Removed {}", self.to_path(locator)?);
        Ok(())
    }

    /// Returns the size of the object stored at the given locator.
    #[inline]
    fn size(&self, locator: &Locator) -> Result<u64, CoordinatorError> {
        trace!("Fetching size of {}", self.to_path(locator)?);

        // Check that the given locator exists in storage.
        if !self.exists(locator) {
            error!("Locator missing in call to size() in storage.");
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Acquire the manifest file read lock.
        let manifest = self.manifest.read().unwrap();

        // Fetch the file size.
        let size = manifest.size(locator)?;

        trace!("Fetched size of {}", self.to_path(&locator)?);
        Ok(size)
    }
}

impl StorageLocator for Disk {
    #[inline]
    fn to_path(&self, locator: &Locator) -> Result<String, CoordinatorError> {
        self.resolver.to_path(locator)
    }

    #[inline]
    fn to_locator(&self, path: &str) -> Result<Locator, CoordinatorError> {
        self.resolver.to_locator(path)
    }
}

impl StorageObject for Disk {
    /// Returns an object reader for the given locator.
    #[inline]
    fn reader<'a>(&self, locator: &Locator) -> Result<ObjectReader, CoordinatorError> {
        // Check that the locator exists in storage.
        if !self.exists(&locator) {
            let locator = self.to_path(&locator)?;
            error!("Locator {} missing in call to reader() in storage.", locator);
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Check that the given locator is opened in storage.
        if !self.is_open(locator) {
            error!("Locator in call to reader() is not opened in storage.");
            return Err(CoordinatorError::StorageLocatorNotOpen);
        }

        // Acquire the file read lock.
        let reader = self
            .open
            .get(locator)
            .ok_or(CoordinatorError::StorageLockFailed)?
            .read()
            .unwrap();

        match locator {
            Locator::CoordinatorState => Ok(reader),
            Locator::RoundHeight => Ok(reader),
            Locator::RoundState(_) => Ok(reader),
            Locator::RoundFile(round_height) => {
                // Check that the round size is correct.
                let expected = Object::round_file_size(&self.environment);
                let found = self.size(&locator)?;
                debug!("Round {} filesize is {}", round_height, found);
                if found != expected {
                    error!("Contribution file size should be {} but found {}", expected, found);
                    return Err(CoordinatorError::RoundFileSizeMismatch.into());
                }
                Ok(reader)
            }
            Locator::ContributionFile(round_height, chunk_id, _, verified) => {
                // Check that the contribution size is correct.
                let expected = Object::contribution_file_size(&self.environment, *chunk_id, *verified);
                let found = self.size(&locator)?;
                debug!("Round {} chunk {} filesize is {}", round_height, chunk_id, found);
                if found != expected {
                    error!("Contribution file size should be {} but found {}", expected, found);
                    return Err(CoordinatorError::ContributionFileSizeMismatch.into());
                }
                Ok(reader)
            }
            Locator::ContributionFileSignature(_, _, _, _) => Ok(reader),
        }
    }

    /// Returns an object writer for the given locator.
    #[inline]
    fn writer(&self, locator: &Locator) -> Result<ObjectWriter, CoordinatorError> {
        // Check that the locator exists in storage.
        if !self.exists(&locator) {
            let locator = self.to_path(&locator)?;
            error!("Locator {} missing in call to writer() in storage.", locator);
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Check that the given locator is opened in storage.
        if !self.is_open(locator) {
            error!("Locator in call to writer() is not opened in storage.");
            return Err(CoordinatorError::StorageLocatorNotOpen);
        }

        // Acquire the file write lock.
        let writer = self
            .open
            .get(locator)
            .ok_or(CoordinatorError::StorageLockFailed)?
            .write()
            .unwrap();

        match locator {
            Locator::CoordinatorState => Ok(writer),
            Locator::RoundHeight => Ok(writer),
            Locator::RoundState(_) => Ok(writer),
            Locator::RoundFile(_) => {
                // Check that the round size is correct.
                let expected = Object::round_file_size(&self.environment);
                let found = self.size(&locator)?;
                debug!("File size of {} is {}", self.to_path(locator)?, found);
                if found != expected {
                    error!("Contribution file size should be {} but found {}", expected, found);
                    return Err(CoordinatorError::RoundFileSizeMismatch.into());
                }
                Ok(writer)
            }
            Locator::ContributionFile(_, chunk_id, _, verified) => {
                // Check that the contribution size is correct.
                let expected = Object::contribution_file_size(&self.environment, *chunk_id, *verified);
                let found = self.size(&locator)?;
                debug!("File size of {} is {}", self.to_path(locator)?, found);
                if found != expected {
                    error!("Contribution file size should be {} but found {}", expected, found);
                    return Err(CoordinatorError::ContributionFileSizeMismatch.into());
                }
                Ok(writer)
            }
            Locator::ContributionFileSignature(_, _, _, _) => Ok(writer),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializedDiskManifest {
    open: BTreeSet<String>,
    locators: BTreeSet<String>,
}

#[derive(Debug)]
struct DiskManifest {
    open: HashSet<Locator>,
    locators: HashSet<Locator>,
    resolver: DiskResolver,
}

impl DiskManifest {
    /// Load the manifest for storage from disk.
    #[inline]
    fn load(base_directory: &str) -> Result<Self, CoordinatorError> {
        // Check the base directory exists.
        if !Path::new(base_directory).exists() {
            // Create the base directory if it does not exist.
            fs::create_dir_all(base_directory).expect("unable to create the base directory");
        }

        // Create the resolver.
        let resolver = DiskResolver::new(base_directory);

        // Load the manifest.
        match Path::new(&resolver.manifest()).exists() {
            // Case 1 - A manifest exists on disk, load the locators from the manifest.
            true => {
                // Read the serialized paths from the manifest.
                let serialized = fs::read_to_string(&Path::new(&resolver.manifest()))?;

                // Check that all locator paths exist on disk.
                let manifest: SerializedDiskManifest = serde_json::from_str(&serialized)?;
                {
                    // Check that all `open` locators exist in the set of all `locators`.
                    for open in &manifest.open {
                        if !manifest.locators.contains(open) {
                            error!("{} is opened but missing in the manifest locators", open);
                            return Err(CoordinatorError::LocatorFileMissing);
                        }
                    }

                    // Check that all `locators` exist on disk.
                    for locator in &manifest.locators {
                        if !Path::new(locator).is_file() {
                            error!("{} is in the manifest locators but missing on disk", locator);
                            return Err(CoordinatorError::LocatorFileMissing);
                        }
                    }
                }

                // Fetch the open locators from the manifest.
                let open: HashSet<Locator> = manifest
                    .open
                    .par_iter()
                    .map(|path| resolver.to_locator(&path).unwrap())
                    .collect();

                // Fetch all locators from the manifest.
                let locators: HashSet<Locator> = manifest
                    .locators
                    .par_iter()
                    .map(|path| resolver.to_locator(&path).unwrap())
                    .collect();

                Ok(Self {
                    open,
                    locators,
                    resolver,
                })
            }
            // Case 2 - No manifest exists on disk, create and store a new instance of `DiskManifest`.
            false => {
                // Serialize a new manifest.
                let serialized = serde_json::to_string_pretty(&SerializedDiskManifest::default())?;

                // Write the serialized manifest to disk.
                fs::write(Path::new(&resolver.manifest()), serialized)?;

                Ok(Self {
                    open: HashSet::default(),
                    locators: HashSet::default(),
                    resolver,
                })
            }
        }
    }

    #[inline]
    fn create_file(&mut self, locator: &Locator, size: Option<u64>) -> Result<File, CoordinatorError> {
        // Check if the file already exists.
        if self.locators.contains(locator) {
            return Err(CoordinatorError::LocatorFileAlreadyExists);
        }

        // Check if the file is already open.
        if self.open.contains(locator) {
            return Err(CoordinatorError::LocatorFileAlreadyExistsAndOpen);
        }

        // If the locator is a contribution file, initialize its directory.
        if let Locator::ContributionFile(round_height, chunk_id, _, _) = locator {
            self.resolver.chunk_directory_init(*round_height, *chunk_id);
        }

        // Load the file path.
        let path = self.resolver.to_path(&locator)?;

        // Open the file.
        let file = OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;

        // Set the initial file size.
        file.set_len(size.unwrap_or(1))?;

        // Add the file to the set of locator files.
        self.locators.insert(locator.clone());

        // Add the file to the set of open files.
        self.open.insert(locator.clone());

        // Save the updated state.
        self.save()?;

        Ok(file)
    }

    #[allow(dead_code)]
    #[inline]
    fn open_file(&mut self, locator: &Locator) -> Result<File, CoordinatorError> {
        // Check if the file exists.
        if !self.locators.contains(locator) {
            error!("Locator missing in call to open_file() in storage.");
            return Err(CoordinatorError::LocatorFileMissing);
        }

        // Check if the file is already open.
        if self.open.contains(locator) {
            return Err(CoordinatorError::LocatorFileAlreadyOpen);
        }

        // Load the file path.
        let path = self.resolver.to_path(&locator)?;

        // Open the file.
        let file = OpenOptions::new().read(true).write(true).open(&path)?;

        // Add the file to the set of open files.
        self.open.insert(locator.clone());

        // Save the updated state.
        self.save()?;

        Ok(file)
    }

    #[inline]
    fn reopen_file(&self, locator: &Locator) -> Result<File, CoordinatorError> {
        // Check that the file exists.
        if !self.locators.contains(locator) {
            error!("Locator missing in call to reopen_file() in storage.");
            return Err(CoordinatorError::LocatorFileMissing);
        }

        // Check that the file is open.
        if !self.open.contains(locator) {
            return Err(CoordinatorError::LocatorFileNotOpen);
        }

        // Load the file path.
        let path = self.resolver.to_path(&locator)?;

        // Open the file.
        let file = OpenOptions::new().read(true).write(true).open(&path)?;

        Ok(file)
    }

    #[inline]
    fn resize_file(&mut self, locator: &Locator, size: u64) -> Result<File, CoordinatorError> {
        // Check that the file exists.
        if !self.locators.contains(locator) {
            error!("Locator missing in call to close_file() in storage.");
            return Err(CoordinatorError::LocatorFileMissing);
        }

        // Check that the file is open.
        if !self.open.contains(locator) {
            return Err(CoordinatorError::LocatorFileShouldBeOpen);
        }

        // Load the file path.
        let path = self.resolver.to_path(&locator)?;

        // Open the file.
        let file = OpenOptions::new().read(true).write(true).open(&path)?;

        // Resize the file.
        file.set_len(size)?;

        Ok(file)
    }

    #[allow(dead_code)]
    #[inline]
    fn close_file(&mut self, locator: &Locator) -> Result<(), CoordinatorError> {
        // Check that the file exists.
        if !self.locators.contains(locator) {
            error!("Locator missing in call to close_file() in storage.");
            return Err(CoordinatorError::LocatorFileMissing);
        }

        // Check that the file is open.
        if !self.open.contains(locator) {
            return Err(CoordinatorError::LocatorFileShouldBeOpen);
        }

        // Remove the file from the set of open files.
        self.open.remove(locator);

        // Save the updated state.
        self.save()?;

        Ok(())
    }

    #[inline]
    fn remove_file(&mut self, locator: &Locator) -> Result<(), CoordinatorError> {
        // Check that the file exists.
        if !self.locators.contains(locator) {
            error!("Locator missing in call to remove_file() in storage.");
            return Err(CoordinatorError::LocatorFileMissing);
        }

        // Fetch the locator file path.
        let path = self.resolver.to_path(locator)?;

        trace!("Removing file {}", path);
        fs::remove_file(path.clone())?;
        trace!("Removed file {}", path);

        // Remove the file from the set of locator files.
        self.locators.remove(locator);

        // Remove the file from the set of open files.
        self.open.remove(locator);

        // Save the updated state.
        self.save()?;

        Ok(())
    }

    #[inline]
    fn save(&mut self) -> Result<(), CoordinatorError> {
        // Serialize the open locators.
        let open: BTreeSet<String> = self
            .open
            .par_iter()
            .map(|locator| self.resolver.to_path(&locator).unwrap())
            .collect();

        // Serialize all locators.
        let locators: BTreeSet<String> = self
            .locators
            .par_iter()
            .map(|locator| self.resolver.to_path(&locator).unwrap())
            .collect();

        // Serialize the manifest.
        let serialized = serde_json::to_string_pretty(&SerializedDiskManifest { open, locators })?;

        // Write the serialized manifest to disk.
        fs::write(Path::new(&self.resolver.manifest()), serialized)?;

        Ok(())
    }

    #[inline]
    fn size(&self, locator: &Locator) -> Result<u64, CoordinatorError> {
        // Check that the given locator exists in storage.
        if !self.locators.contains(locator) {
            error!("Locator missing in call to size() in storage.");
            return Err(CoordinatorError::StorageLocatorMissing);
        }

        // Load the file path.
        let path = self.resolver.to_path(&locator)?;

        // Open the file.
        let file = OpenOptions::new().read(true).write(true).open(&path)?;

        Ok(file.metadata()?.len())
    }

    #[inline]
    fn contains(&self, locator: &Locator) -> bool {
        self.locators.contains(locator)
    }
}

#[derive(Debug)]
struct DiskResolver {
    base: String,
}

impl DiskResolver {
    #[inline]
    fn new(base: &str) -> Self {
        Self { base: base.to_string() }
    }
}

impl StorageLocator for DiskResolver {
    #[inline]
    fn to_path(&self, locator: &Locator) -> Result<String, CoordinatorError> {
        let path = match locator {
            Locator::CoordinatorState => format!("{}/coordinator.json", self.base),
            Locator::RoundHeight => format!("{}/round_height", self.base),
            Locator::RoundState(round_height) => format!("{}/state.json", self.round_directory(*round_height)),
            Locator::RoundFile(round_height) => {
                let round_directory = self.round_directory(*round_height);
                format!("{}/round_{}.verified", round_directory, *round_height)
            }
            Locator::ContributionFile(round_height, chunk_id, contribution_id, verified) => {
                // Fetch the chunk directory path.
                let path = self.chunk_directory(*round_height, *chunk_id);
                match verified {
                    // Set the contribution locator as `{chunk_directory}/contribution_{contribution_id}.verified`.
                    true => format!("{}/contribution_{}.verified", path, contribution_id),
                    // Set the contribution locator as `{chunk_directory}/contribution_{contribution_id}.unverified`.
                    false => format!("{}/contribution_{}.unverified", path, contribution_id),
                }
            }
            Locator::ContributionFileSignature(round_height, chunk_id, contribution_id, verified) => {
                // Fetch the chunk directory path.
                let path = self.chunk_directory(*round_height, *chunk_id);
                match verified {
                    // Set the contribution locator as `{chunk_directory}/contribution_{contribution_id}.verified.signature`.
                    true => format!("{}/contribution_{}.verified.signature", path, contribution_id),
                    // Set the contribution locator as `{chunk_directory}/contribution_{contribution_id}.unverified.signature`.
                    false => format!("{}/contribution_{}.unverified.signature", path, contribution_id),
                }
            }
        };
        // Sanitize the path.
        Ok(Path::new(&path)
            .to_str()
            .ok_or(CoordinatorError::StorageLocatorFormatIncorrect)?
            .to_string())
    }

    #[inline]
    fn to_locator(&self, path: &str) -> Result<Locator, CoordinatorError> {
        // Sanitize the given path and base to the local OS.
        let mut path = path.to_string();
        let path = {
            // TODO (howardwu): Change this to support absolute paths and OS specific path
            //   conventions that may be non-standard. For now, restrict this to relative paths.
            if !path.starts_with("./") {
                path = format!("./{}", path);
            }

            let path = Path::new(path.as_str());
            let base = Path::new(&self.base);

            // Check that the path matches the expected base.
            if !path.starts_with(base) {
                error!("{:?} does not start with {:?}", path, base);
                return Err(CoordinatorError::StorageLocatorFormatIncorrect);
            }

            path
        };

        // Strip the base prefix.
        let key = path
            .strip_prefix(&format!("{}/", self.base))
            .map_err(|_| CoordinatorError::StorageLocatorFormatIncorrect)?;

        let key = key.to_str().ok_or(CoordinatorError::StorageLocatorFormatIncorrect)?;

        // Check if it matches the coordinator state file.
        if key == "coordinator.json" {
            return Ok(Locator::CoordinatorState);
        }

        // Check if it matches the round height.
        if key == "round_height" {
            return Ok(Locator::RoundHeight);
        }

        // Parse the key into its components.
        if let Some((round, remainder)) = key.splitn(2, "/").collect_tuple() {
            // Check if it resembles the round directory.
            if round.starts_with("round_") {
                // Attempt to parse the round string for the round height.
                let round_height = u64::from_str(
                    round
                        .strip_prefix("round_")
                        .ok_or(CoordinatorError::StorageLocatorFormatIncorrect)?,
                )?;

                // Check if it matches the round directory.
                if round == &format!("round_{}", round_height) {
                    /* In round directory */

                    // Check if it matches the round state.
                    if remainder == "state.json" {
                        return Ok(Locator::RoundState(round_height));
                    }

                    // Check if it matches the round file.
                    if remainder == format!("round_{}.verified", round_height) {
                        return Ok(Locator::RoundFile(round_height));
                    }

                    // Parse the path into its components.
                    if let Some((chunk, path)) = remainder.splitn(2, "/").collect_tuple() {
                        // Check if it resembles the chunk directory.
                        if chunk.starts_with("chunk_") {
                            // Attempt to parse the path string for the chunk ID.
                            let chunk_id = u64::from_str(
                                chunk
                                    .strip_prefix("chunk_")
                                    .ok_or(CoordinatorError::StorageLocatorFormatIncorrect)?,
                            )?;

                            // Check if it matches the chunk directory.
                            if chunk == &format!("chunk_{}", chunk_id) {
                                /* In chunk directory */

                                // Check if it matches the contribution file.
                                if path.starts_with("contribution_") {
                                    let (id, extension) = path
                                        .strip_prefix("contribution_")
                                        .ok_or(CoordinatorError::StorageLocatorFormatIncorrect)?
                                        .splitn(2, '.')
                                        .collect_tuple()
                                        .ok_or(CoordinatorError::StorageLocatorFormatIncorrect)?;
                                    let contribution_id = u64::from_str(id)?;

                                    // Check if it matches a contribution file signature for an unverified contribution.
                                    if extension == "unverified.signature" {
                                        return Ok(Locator::ContributionFileSignature(
                                            round_height,
                                            chunk_id,
                                            contribution_id,
                                            false,
                                        ));
                                    }

                                    // Check if it matches a contribution file signature for a verified contribution.
                                    if extension == "verified.signature" {
                                        return Ok(Locator::ContributionFileSignature(
                                            round_height,
                                            chunk_id,
                                            contribution_id,
                                            true,
                                        ));
                                    }

                                    // Check if it matches a unverified contribution file.
                                    if extension == "unverified" {
                                        return Ok(Locator::ContributionFile(
                                            round_height,
                                            chunk_id,
                                            contribution_id,
                                            false,
                                        ));
                                    }

                                    // Check if it matches a unverified contribution file.
                                    if extension == "verified" {
                                        return Ok(Locator::ContributionFile(
                                            round_height,
                                            chunk_id,
                                            contribution_id,
                                            true,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(CoordinatorError::StorageLocatorFormatIncorrect)
    }
}

impl DiskResolver {
    /// Returns the storage manifest file path.
    #[inline]
    fn manifest(&self) -> String {
        format!("{}/manifest.json", self.base)
    }

    /// Returns the round directory for a given round height from the coordinator.
    #[inline]
    fn round_directory(&self, round_height: u64) -> String {
        format!("{}/round_{}", self.base, round_height)
    }

    /// Returns the chunk directory for a given round height and chunk ID from the coordinator.
    #[inline]
    fn chunk_directory(&self, round_height: u64, chunk_id: u64) -> String {
        // Fetch the transcript directory path.
        let path = self.round_directory(round_height);

        // Format the chunk directory as `{round_directory}/chunk_{chunk_id}`.
        format!("{}/chunk_{}", path, chunk_id)
    }

    /// Initializes the chunk directory for a given  round height, and chunk ID.
    #[inline]
    fn chunk_directory_init(&self, round_height: u64, chunk_id: u64) {
        // If the round directory does not exist, attempt to initialize the directory path.
        let path = self.round_directory(round_height);
        if !Path::new(&path).exists() {
            std::fs::create_dir_all(&path).expect("unable to create the round directory");
        }

        // If the chunk directory does not exist, attempt to initialize the directory path.
        let path = self.chunk_directory(round_height, chunk_id);
        if !Path::new(&path).exists() {
            std::fs::create_dir_all(&path).expect("unable to create the chunk directory");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::testing::prelude::*;

    #[test]
    fn test_to_path_coordinator_state() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            "./transcript/test/coordinator.json",
            locator.to_path(&Locator::CoordinatorState).unwrap()
        );
    }

    #[test]
    fn test_to_locator_coordinator_state() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            Locator::CoordinatorState,
            locator.to_locator("./transcript/test/coordinator.json").unwrap(),
        );
    }

    #[test]
    fn test_to_path_round_height() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            "./transcript/test/round_height",
            locator.to_path(&Locator::RoundHeight).unwrap()
        );
    }

    #[test]
    fn test_to_locator_round_height() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            Locator::RoundHeight,
            locator.to_locator("./transcript/test/round_height").unwrap(),
        );
    }

    #[test]
    fn test_to_path_round_state() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            "./transcript/test/round_0/state.json",
            locator.to_path(&Locator::RoundState(0)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_1/state.json",
            locator.to_path(&Locator::RoundState(1)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_2/state.json",
            locator.to_path(&Locator::RoundState(2)).unwrap()
        );
    }

    #[test]
    fn test_to_locator_round_state() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            Locator::RoundState(0),
            locator.to_locator("./transcript/test/round_0/state.json").unwrap(),
        );
        assert_eq!(
            Locator::RoundState(1),
            locator.to_locator("./transcript/test/round_1/state.json").unwrap(),
        );
        assert_eq!(
            Locator::RoundState(2),
            locator.to_locator("./transcript/test/round_2/state.json").unwrap(),
        );
    }

    #[test]
    fn test_to_path_round_file() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            "./transcript/test/round_0/round_0.verified",
            locator.to_path(&Locator::RoundFile(0)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_1/round_1.verified",
            locator.to_path(&Locator::RoundFile(1)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_2/round_2.verified",
            locator.to_path(&Locator::RoundFile(2)).unwrap()
        );
    }

    #[test]
    fn test_to_locator_round_file() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            Locator::RoundFile(0),
            locator
                .to_locator("./transcript/test/round_0/round_0.verified")
                .unwrap(),
        );
        assert_eq!(
            Locator::RoundFile(1),
            locator
                .to_locator("./transcript/test/round_1/round_1.verified")
                .unwrap(),
        );
        assert_eq!(
            Locator::RoundFile(2),
            locator
                .to_locator("./transcript/test/round_2/round_2.verified")
                .unwrap(),
        );
    }

    #[test]
    fn test_to_path_contribution_file() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            "./transcript/test/round_0/chunk_0/contribution_0.unverified",
            locator.to_path(&Locator::ContributionFile(0, 0, 0, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_0/chunk_0/contribution_0.verified",
            locator.to_path(&Locator::ContributionFile(0, 0, 0, true)).unwrap()
        );

        assert_eq!(
            "./transcript/test/round_1/chunk_0/contribution_0.unverified",
            locator.to_path(&Locator::ContributionFile(1, 0, 0, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_1/chunk_0/contribution_0.verified",
            locator.to_path(&Locator::ContributionFile(1, 0, 0, true)).unwrap()
        );

        assert_eq!(
            "./transcript/test/round_0/chunk_1/contribution_0.unverified",
            locator.to_path(&Locator::ContributionFile(0, 1, 0, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_0/chunk_1/contribution_0.verified",
            locator.to_path(&Locator::ContributionFile(0, 1, 0, true)).unwrap()
        );

        assert_eq!(
            "./transcript/test/round_0/chunk_0/contribution_1.unverified",
            locator.to_path(&Locator::ContributionFile(0, 0, 1, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_0/chunk_0/contribution_1.verified",
            locator.to_path(&Locator::ContributionFile(0, 0, 1, true)).unwrap()
        );

        assert_eq!(
            "./transcript/test/round_1/chunk_1/contribution_0.unverified",
            locator.to_path(&Locator::ContributionFile(1, 1, 0, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_1/chunk_1/contribution_0.verified",
            locator.to_path(&Locator::ContributionFile(1, 1, 0, true)).unwrap()
        );

        assert_eq!(
            "./transcript/test/round_1/chunk_0/contribution_1.unverified",
            locator.to_path(&Locator::ContributionFile(1, 0, 1, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_1/chunk_0/contribution_1.verified",
            locator.to_path(&Locator::ContributionFile(1, 0, 1, true)).unwrap()
        );

        assert_eq!(
            "./transcript/test/round_0/chunk_1/contribution_1.unverified",
            locator.to_path(&Locator::ContributionFile(0, 1, 1, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_0/chunk_1/contribution_1.verified",
            locator.to_path(&Locator::ContributionFile(0, 1, 1, true)).unwrap()
        );

        assert_eq!(
            "./transcript/test/round_1/chunk_1/contribution_1.unverified",
            locator.to_path(&Locator::ContributionFile(1, 1, 1, false)).unwrap()
        );
        assert_eq!(
            "./transcript/test/round_1/chunk_1/contribution_1.verified",
            locator.to_path(&Locator::ContributionFile(1, 1, 1, true)).unwrap()
        );
    }

    #[test]
    fn test_to_locator_contribution_file() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_0.unverified")
                .unwrap(),
            Locator::ContributionFile(0, 0, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_0.verified")
                .unwrap(),
            Locator::ContributionFile(0, 0, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_0.unverified")
                .unwrap(),
            Locator::ContributionFile(1, 0, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_0.verified")
                .unwrap(),
            Locator::ContributionFile(1, 0, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_0.unverified")
                .unwrap(),
            Locator::ContributionFile(0, 1, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_0.verified")
                .unwrap(),
            Locator::ContributionFile(0, 1, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_1.unverified")
                .unwrap(),
            Locator::ContributionFile(0, 0, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_1.verified")
                .unwrap(),
            Locator::ContributionFile(0, 0, 1, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_0.unverified")
                .unwrap(),
            Locator::ContributionFile(1, 1, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_0.verified")
                .unwrap(),
            Locator::ContributionFile(1, 1, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_1.unverified")
                .unwrap(),
            Locator::ContributionFile(1, 0, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_1.verified")
                .unwrap(),
            Locator::ContributionFile(1, 0, 1, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_1.unverified")
                .unwrap(),
            Locator::ContributionFile(0, 1, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_1.verified")
                .unwrap(),
            Locator::ContributionFile(0, 1, 1, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_1.unverified")
                .unwrap(),
            Locator::ContributionFile(1, 1, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_1.verified")
                .unwrap(),
            Locator::ContributionFile(1, 1, 1, true)
        );
    }

    #[test]
    fn test_to_locator_contribution_file_signature() {
        let locator = DiskResolver::new("./transcript/test");

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_0.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 0, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_0.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 0, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_0.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 0, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_0.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 0, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_0.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 1, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_0.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 1, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_1.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 0, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_0/contribution_1.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 0, 1, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_0.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 1, 0, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_0.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 1, 0, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_1.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 0, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_0/contribution_1.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 0, 1, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_1.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 1, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_0/chunk_1/contribution_1.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(0, 1, 1, true)
        );

        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_1.unverified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 1, 1, false)
        );
        assert_eq!(
            locator
                .to_locator("./transcript/test/round_1/chunk_1/contribution_1.verified.signature")
                .unwrap(),
            Locator::ContributionFileSignature(1, 1, 1, true)
        );
    }
}
