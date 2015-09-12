/*
 * Copyright (C) 2013 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef STUB_MTP_DATABASE_H_
#define STUB_MTP_DATABASE_H_

#include <mtp.h>
#include <MtpDatabase.h>
#include <MtpDataPacket.h>
#include <MtpStringBuffer.h>
#include <MtpObjectInfo.h>
#include <MtpProperty.h>
#include <MtpDebug.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <tuple>
#include <exception>
#include <sys/inotify.h>
#include <algorithm>

#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>
#include <queue>


struct buffer_size {
public:
	buffer_size()
		: s(NULL), _len(0)
	{
	}
	buffer_size(const uint8_t *buf, size_t len)
		: _len(len)
	{
		s = new uint8_t[_len];
		if (!s) {
			printf("allocate buffer failed");
			_len = 0;
		}
		if (len > 0)
			std::memcpy(s, buf, len);

	}
	~buffer_size()
	{
		if (_len > 0)
			delete [] s;
	}

public:
	uint8_t *data()
	{
		return s;
	}
	uint8_t size()
	{
		return _len;
	}

private:
	uint8_t *s;
	size_t _len;
};

class path {
public:
	path():s("")
	{
	}
	path(std::string p):s(p)
	{
	}
	void setPath(std::string p)
	{
		s = p;
	}
	std::string string()
	{
		return s;
	}
	std::string filename()
	{
		int n = s.find_last_of("/\\");
		return s.substr(n + 1);
	}
	std::string getPath()
	{
		int n = s.find_last_of("/\\");
		return s.substr(0, n);
	}
	std::string extension()
	{
		int n = s.find_first_of(".");
		return s.substr(n + 1);
	}
private:
	std::string s;
};

size_t file_size(path &p)
{
	FILE* fp;
	int n = 0;

	fp = fopen(p.string().c_str(),  "rb");
	if (fp == NULL) {
		perror("fopen:");
		return 0;
	}

	fseek(fp, 0, SEEK_END);	
	n = ftell(fp);
	fclose(fp);

	return n;
}

bool is_directory(path &p)
{
	struct stat _stat;
	if (lstat(p.string().c_str(), &_stat) < 0) {
		perror("lstat:");
		return false;
	}
	if (S_ISDIR(_stat.st_mode))
		return true;
	return false;
}

bool exists(path &p)
{
	if (access(p.string().c_str(), F_OK) < 0)
		return false;
	return true;
}

std::string _basename(const char *p)
{
	std::string s(p);
	int n = s.find_last_of("/\\");
	s = s.substr(n + 1);
	n = s.find_last_of(".");
	return s.substr(0, n);
}

void to_upper(std::string &s)
{
	for (size_t i = 0; i < s.size(); ++i) {
		if (s[i] >= 'a' && s[i] <= 'z')
			s[i] = s[i] - 'a' + 'A';
	}
}

bool get_file_list(path &p, std::vector<path> &v)
{
	if (!is_directory(p))
		return false;
	
	struct dirent *dirp;
	DIR *dp;

	if ((dp = opendir(p.getPath().c_str())) == NULL)
		return false;
	while ((dirp = readdir(dp)) != NULL) {
		if (!strcmp(dirp->d_name, ".") 
			|| !strcmp(dirp->d_name, "..")) 
			continue;
		path sub(p.getPath() + "/" + std::string(dirp->d_name));
		v.push_back(sub);
	}

	if (closedir(dp) < 0)
		return false;

	return true;
}

std::queue<struct buffer_size *> queueBuffer;
pthread_mutex_t mutex;

namespace android
{
class UcloudMtpDatabase : public android::MtpDatabase {
//public:
private:
    struct DbEntry
    {
        MtpStorageID storage_id;
        MtpObjectFormat object_format;
        MtpObjectHandle parent;
        size_t object_size;
        std::string display_name;
        std::string path;
        int watch_fd;
    };

    MtpServer* local_server;
    uint32_t counter;
    std::map<MtpObjectHandle, DbEntry> db;
    std::map<std::string, MtpObjectFormat> formats;

    /* FIXME */
    pthread_t notifier_thread;
    pthread_t proc_thread;

    int inotify_fd;
    bool exit;

    MtpObjectFormat guess_object_format(std::string extension)
    {
        std::map<std::string, MtpObjectFormat>::iterator it;

        it = formats.find(extension);
        if (it == formats.end()) {
            to_upper(extension);
            it = formats.find(extension);
            if (it == formats.end()) {
                return MTP_FORMAT_UNDEFINED;
            }
	}

	return it->second;
    }

    int setup_dir_inotify(path p)
    {
        return inotify_add_watch(inotify_fd,
                                 p.string().c_str(),
                                 IN_MODIFY | IN_CREATE | IN_DELETE);
    }

    
    void add_file_entry(path p, MtpObjectHandle parent)
    {
        MtpObjectHandle handle = counter;
        DbEntry entry;

        counter++;

        if (is_directory(p)) {
            std::string name = p.filename();

            // we don't want to expose some parts
            if (name == ".cryptofs" || name == ".sysservice")
                return;

            entry.storage_id = MTP_STORAGE_FIXED_RAM;
            entry.parent = parent;
            entry.display_name = std::string(p.filename());
            entry.path = p.string();
            entry.object_format = MTP_FORMAT_ASSOCIATION;
            entry.object_size = 0;
            entry.watch_fd = setup_dir_inotify(p);

std::cout << "Adding \"" << p.string() << "\"" << std::endl;

            db.insert( std::pair<MtpObjectHandle, DbEntry>(handle, entry) );

            if (local_server)
                local_server->sendObjectAdded(handle);

            parse_directory (p, handle);
        } else {
            try {
                entry.storage_id = MTP_STORAGE_FIXED_RAM;
                entry.parent = parent;
                entry.display_name = p.filename();
                entry.path = p.string();
                entry.object_format = guess_object_format(p.extension());
                entry.object_size = file_size(p);

std::cout << "Adding \"" << p.string() << "\"" << std::endl;

                db.insert( std::pair<MtpObjectHandle, DbEntry>(handle, entry) );

                if (local_server)
                    local_server->sendObjectAdded(handle);

            } catch (...) {
std::cout << "There was an error reading file properties" << std::endl;
            }
        }
    }

    void parse_directory(path p, MtpObjectHandle parent)
    {
	DbEntry entry;
        std::vector<path> v;

	/* FIXME, ok */
	get_file_list(p, v);

        for (std::vector<path>::const_iterator it(v.begin()), it_end(v.end()); it != it_end; ++it)
        {
            add_file_entry(*it, parent);
        }
    }

    void readFiles(const std::string& sourcedir)
    {
        path p (sourcedir);

        DbEntry entry;
        MtpObjectHandle handle = counter++;

        try {
            if (exists(p)) {
                if (is_directory(p)) {
                    entry.storage_id = MTP_STORAGE_FIXED_RAM;
                    entry.parent = MTP_PARENT_ROOT;
                    entry.display_name = p.filename();
                    entry.path = p.string();
                    entry.object_format = MTP_FORMAT_ASSOCIATION;
                    entry.object_size = 0;
                    entry.watch_fd = setup_dir_inotify(p);

                    db.insert( std::pair<MtpObjectHandle, DbEntry>(handle, entry) );

                    parse_directory (p, handle);
                }
            } else
std::cout << p.string() << " does not exist\n" << std::endl;
        }
        catch (...) {
std::cout << "An unexpected error has occurred" << std::endl;
        }

    }

    virtual void run_select()
    {
		int ret;
		int max = inotify_fd + 1;
		fd_set rfds;
		uint8_t buf[2048];

		pthread_mutex_lock(&mutex);
		while (!queueBuffer.empty())
			queueBuffer.pop();
		pthread_mutex_unlock(&mutex);

		while (exit == false) {
			struct timeval tv = {2, 0};
			FD_ZERO(&rfds);
			FD_SET(inotify_fd, &rfds);

			ret = select(max, &rfds, NULL, NULL, &tv);
			if (ret < 0) {
				perror("thread:run(): select");
				continue;
			}
			if (ret == 0) {
				printf("select had timeout!");
				continue;
			}
			if (FD_ISSET(inotify_fd, &rfds)) {
				int len;
				len = read(inotify_fd, buf, sizeof(buf));
				if (len < 0) {
					perror("thread:run(): read from inotify_fd");
					continue;
				}
				struct buffer_size *bs = new buffer_size(buf, len);
				if (bs) {
					pthread_mutex_lock(&mutex);
					queueBuffer.push(bs);
					pthread_mutex_unlock(&mutex);
				}
			}
		}
    }

    virtual void run_proc()
    {
		while (exit == false) {
			struct buffer_size *bs;
			pthread_mutex_lock(&mutex);
			if (queueBuffer.empty()) {
				sleep(1);
				pthread_mutex_unlock(&mutex);
				continue;
			}
			if (!queueBuffer.empty()) {
				bs = (struct buffer_size *)queueBuffer.front();
				queueBuffer.pop();
			}
			pthread_mutex_unlock(&mutex);
			inotify_handler(bs->data(), bs->size());
			delete bs;
		}
    }

    static void *interThreadEntry1(void *ctx)
    {
        ((UcloudMtpDatabase *)ctx)->run_select();
    }

    static void *interThreadEntry2(void *ctx)
    {
        ((UcloudMtpDatabase *)ctx)->run_proc();
    }

	/* FIXME */
    void inotify_handler(uint8_t *buf, size_t transferred)
    {
        size_t processed = 0;
     
        while(transferred - processed >= sizeof(inotify_event))
        {
            uint8_t* cdata = buf + processed;
            const inotify_event* ievent = (const inotify_event *)cdata;
            MtpObjectHandle parent;
     
            processed += sizeof(inotify_event) + ievent->len;
     
	/* FIXME */
	    for (std::map<MtpObjectHandle, DbEntry>::iterator i = db.begin(); i != db.end(); ++i) {
                if (i->second.watch_fd == ievent->wd) {
                    parent = i->first;
                    break;
                }
	    }

            path p(db.at(parent).path + "/" + ievent->name);

            if(ievent->len > 0 && ievent->mask & IN_MODIFY)
            {
std::cout << __PRETTY_FUNCTION__ << ": file modified: " << p.string() << std::endl;
		for (std::map<MtpObjectHandle, DbEntry>::iterator i = db.begin(); i != db.end(); ++i) {
                    if (i->second.path == p.string()) {
                        try {
std::cout << "new size: " << file_size(p) << std::endl;
                            i->second.object_size = file_size(p);
                        } catch (...) {
std::cout << "There was an error reading file properties" << std::endl;
                        }
                    }
                }
            }
            else if(ievent->len > 0 && ievent->mask & IN_CREATE)
            {
std::cout << __PRETTY_FUNCTION__ << ": file created: " << p.string() << std::endl;

                /* try to deal with it as if it was a file. */
                add_file_entry(p, parent);
            }
            else if(ievent->len > 0 && ievent->mask & IN_DELETE)
            {
std::cout << __PRETTY_FUNCTION__ << ": file deleted: " << p.string() << std::endl;
		for (std::map<MtpObjectHandle, DbEntry>::iterator i = db.begin(); i != db.end(); ++i) {
                    if (i->second.path == p.string()) {
std::cout << "deleting file at handle " << i->first << std::endl;
                        deleteFile(i->first);
                        if (local_server)
                            local_server->sendObjectRemoved(i->first);
                        break;
                    }
                }
            }
        }
    }

public:
    UcloudMtpDatabase(const char *dir):
        counter(1)
    {
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".gif", MTP_FORMAT_GIF));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".png", MTP_FORMAT_PNG));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".jpeg", MTP_FORMAT_JFIF));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".ogg", MTP_FORMAT_OGG));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".mp3", MTP_FORMAT_MP3));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".wav", MTP_FORMAT_WAV));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".wma", MTP_FORMAT_WMA));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".aac", MTP_FORMAT_AAC));
	formats.insert(std::map<std::string, MtpObjectFormat>::value_type(".flac", MTP_FORMAT_FLAC));

	std::string basedir (dir);

    local_server = NULL;

    inotify_fd = inotify_init();
    if (inotify_fd <= 0)
        std::cout << "Unable to initialize inotify" << std::endl;

	db = std::map<MtpObjectHandle, DbEntry>();

	exit = false;
	pthread_mutex_init(&mutex, NULL);
	pthread_create(&notifier_thread, NULL, &android::UcloudMtpDatabase::interThreadEntry1, this);
	pthread_create(&proc_thread, NULL, &android::UcloudMtpDatabase::interThreadEntry2, this);

	parse_directory(basedir, MTP_PARENT_ROOT);

std::cout << "Added " << counter << " entries to the database." << std::endl;
    }

    virtual ~UcloudMtpDatabase() {
    	exit = true;
    	sleep(2);
		pthread_join(notifier_thread, NULL);
        pthread_join(proc_thread, NULL);
        close(inotify_fd);
    }

    // called from SendObjectInfo to reserve a database entry for the incoming file
    virtual MtpObjectHandle beginSendObject(
        const MtpString& path,
        MtpObjectFormat format,
        MtpObjectHandle parent,
        MtpStorageID storage,
        uint64_t size,
        time_t modified)
    {
	DbEntry entry;
	MtpObjectHandle handle = counter;

        if (parent == 0)
            return kInvalidObjectHandle;

std::cout << __PRETTY_FUNCTION__ << ": " << path << " - " << parent << std::endl;

        entry.storage_id = storage;
        entry.parent = parent;
        entry.display_name = std::string(_basename(path.c_str()));
        entry.path = path;
        entry.object_format = format;
        entry.object_size = size;

        db.insert( std::pair<MtpObjectHandle, DbEntry>(handle, entry) );

	   counter++;

        return handle; 
    }

    // called to report success or failure of the SendObject file transfer
    // success should signal a notification of the new object's creation,
    // failure should remove the database entry created in beginSendObject
    virtual void endSendObject(
        const MtpString& _path,
        MtpObjectHandle handle,
        MtpObjectFormat format,
        bool succeeded)
    {
std::cout << __PRETTY_FUNCTION__ << ": " << _path << std::endl;

	if (!succeeded) {
            db.erase(handle);
        } else {
            path p (_path);

            if (format != MTP_FORMAT_ASSOCIATION) {
                /* Resync file size, just in case this is actually an Edit. */
                db.at(handle).object_size = file_size(p);
            }
        }
    }

    virtual MtpObjectHandleList* getObjectList(
        MtpStorageID storageID,
        MtpObjectFormat format,
        MtpObjectHandle parent)
    {
std::cout << __PRETTY_FUNCTION__ << ": " << storageID << ", " << format << ", " << parent << std::endl;
        MtpObjectHandleList* list = NULL;
        try
        {
            std::vector<MtpObjectHandle> keys;

	    /* FIXME */
	    for (std::map<MtpObjectHandle, DbEntry>::iterator i = db.begin(); i != db.end(); ++i) {
                if (i->second.parent == parent)
                    keys.push_back(i->first);
            }

            list = new MtpObjectHandleList(keys);
        } catch(...)
        {
            list = new MtpObjectHandleList();
        }
        
        return list;
    }

    virtual int getNumObjects(
        MtpStorageID storageID,
        MtpObjectFormat format,
        MtpObjectHandle parent)
    {
std::cout << __PRETTY_FUNCTION__ << ": " << storageID << ", " << format << ", " << parent << std::endl;
        try
        {
            return db.size();
        } catch(...)
        {
        }
        
        return 0;
    }

    // callee should delete[] the results from these
    // results can be NULL
    virtual MtpObjectFormatList* getSupportedPlaybackFormats()
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        static const MtpObjectFormatList list = {
            /* Generic files */
            MTP_FORMAT_UNDEFINED,

            /* Supported audio formats */
            MTP_FORMAT_OGG,
            MTP_FORMAT_MP3,
            MTP_FORMAT_WAV,
            MTP_FORMAT_WMA,
            MTP_FORMAT_AAC,
            MTP_FORMAT_FLAC,

            /* Supported video formats */
            // none listed yet, video apparently broken.

            /* Audio album, and album art */
            MTP_FORMAT_ABSTRACT_AUDIO_ALBUM,

            /* Playlists for audio and video */
            MTP_FORMAT_ABSTRACT_AV_PLAYLIST,
        };

	/* FIXME */
        return new MtpObjectFormatList{list};
    }
    
    virtual MtpObjectFormatList* getSupportedCaptureFormats()
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        static const MtpObjectFormatList list = {MTP_FORMAT_ASSOCIATION, MTP_FORMAT_PNG};
        return new MtpObjectFormatList{list};
    }
    
    virtual MtpObjectPropertyList* getSupportedObjectProperties(MtpObjectFormat format)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
	/*
        if (format != MTP_FORMAT_PNG)
            return NULL;
        */
            
        static const MtpObjectPropertyList list = 
        {
            MTP_PROPERTY_STORAGE_ID,
            MTP_PROPERTY_PARENT_OBJECT,
            MTP_PROPERTY_OBJECT_FORMAT,
            MTP_PROPERTY_OBJECT_SIZE,
            MTP_PROPERTY_WIDTH,
            MTP_PROPERTY_HEIGHT,
            MTP_PROPERTY_IMAGE_BIT_DEPTH,
            MTP_PROPERTY_OBJECT_FILE_NAME,
            MTP_PROPERTY_DISPLAY_NAME            
        };
         
        return new MtpObjectPropertyList{list};
    }
    
    virtual MtpDevicePropertyList* getSupportedDeviceProperties()
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        static const MtpDevicePropertyList list = { MTP_DEVICE_PROPERTY_UNDEFINED };
        return new MtpDevicePropertyList{list};
    }

    virtual MtpResponseCode getObjectPropertyValue(
        MtpObjectHandle handle,
        MtpObjectProperty property,
        MtpDataPacket& packet)
    {        
        std::cout << __PRETTY_FUNCTION__
                << " handle: " << handle
                << " property: " << MtpDebug::getObjectPropCodeName(property) << std::endl;

        switch(property)
        {
            case MTP_PROPERTY_STORAGE_ID: packet.putUInt32(db.at(handle).storage_id); break;            
            case MTP_PROPERTY_PARENT_OBJECT: packet.putUInt32(db.at(handle).parent); break;            
            case MTP_PROPERTY_OBJECT_FORMAT: packet.putUInt32(db.at(handle).object_format); break;
            case MTP_PROPERTY_OBJECT_SIZE: packet.putUInt32(db.at(handle).object_size); break;
            case MTP_PROPERTY_DISPLAY_NAME: packet.putString(db.at(handle).display_name.c_str()); break;
            case MTP_PROPERTY_OBJECT_FILE_NAME: packet.putString(db.at(handle).display_name.c_str()); break;
            default: return MTP_RESPONSE_GENERAL_ERROR; break;                
        }
        
        return MTP_RESPONSE_OK;
    }

    virtual MtpResponseCode setObjectPropertyValue(
        MtpObjectHandle handle,
        MtpObjectProperty property,
        MtpDataPacket& packet)
    {
        DbEntry entry;
        MtpStringBuffer buffer;
        std::string oldname;
        std::string newname;
        path oldpath;
        path newpath;

	std::cout << __PRETTY_FUNCTION__
                << " handle: " << handle
                << " property: " << MtpDebug::getObjectPropCodeName(property) << std::endl;

        switch(property)
        {
            case MTP_PROPERTY_OBJECT_FILE_NAME:
                try {
                    entry = db.at(handle);

                    packet.getString(buffer);
                    newname = strdup(buffer);

		    /* OK */
                    oldpath.setPath(entry.path);
                    newpath.setPath(oldpath.getPath() + "/" + newname);

                    rename(oldpath.filename().c_str(), newpath.filename().c_str());

                    db.at(handle).display_name = newname;
                    db.at(handle).path = newpath.string();
                } catch (std::exception& e) {
std::cout << e.what() << std::endl;
                    return MTP_RESPONSE_GENERAL_ERROR;
                } catch (...) {
std::cout << "An unexpected error has occurred" << std::endl;
                    return MTP_RESPONSE_GENERAL_ERROR;
		}

                break;
            default: return MTP_RESPONSE_OPERATION_NOT_SUPPORTED; break;
        }
        
        return MTP_RESPONSE_OK;
    }

    virtual MtpResponseCode getDevicePropertyValue(
        MtpDeviceProperty property,
        MtpDataPacket& packet)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        return MTP_RESPONSE_GENERAL_ERROR;
    }

    virtual MtpResponseCode setDevicePropertyValue(
        MtpDeviceProperty property,
        MtpDataPacket& packet)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        return MTP_RESPONSE_OPERATION_NOT_SUPPORTED;
    }

    virtual MtpResponseCode resetDeviceProperty(
        MtpDeviceProperty property)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        return MTP_RESPONSE_OPERATION_NOT_SUPPORTED;
    }

    virtual MtpResponseCode getObjectPropertyList(
        MtpObjectHandle handle,
        uint32_t format, 
        uint32_t property,
        int groupCode, 
        int depth,
        MtpDataPacket& packet)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        return MTP_RESPONSE_OPERATION_NOT_SUPPORTED;
    }

    virtual MtpResponseCode getObjectInfo(
        MtpObjectHandle handle,
        MtpObjectInfo& info)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;

        info.mHandle = handle;
        info.mStorageID = db.at(handle).storage_id;
        info.mFormat = db.at(handle).object_format;
        info.mProtectionStatus = 0x0;
        info.mCompressedSize = db.at(handle).object_size;
        info.mImagePixWidth = 0;
        info.mImagePixHeight = 0;
        info.mImagePixDepth = 0;
        info.mParent = db.at(handle).parent;
        info.mAssociationType = 0;
        info.mAssociationDesc = 0;
        info.mSequenceNumber = 0;
        info.mName = ::strdup(db.at(handle).display_name.c_str());
        info.mDateCreated = 0;
        info.mDateModified = 0;
        info.mKeywords = ::strdup("ubuntu,touch");
        
        info.print();

        return MTP_RESPONSE_OK;
    }

    virtual void* getThumbnail(MtpObjectHandle handle, size_t& outThumbSize)
    {
        void* result;

	outThumbSize = 0;
	memset(result, 0, outThumbSize);

        return result;
    }

    virtual MtpResponseCode getObjectFilePath(
        MtpObjectHandle handle,
        MtpString& outFilePath,
        int64_t& outFileLength,
        MtpObjectFormat& outFormat)
    {
        DbEntry entry = db.at(handle);

std::cout << __PRETTY_FUNCTION__ << " handle: " << handle << std::endl;

        outFilePath = std::string(entry.path);
        outFileLength = entry.object_size;
        outFormat = entry.object_format;

        return MTP_RESPONSE_OK;
    }

    virtual MtpResponseCode deleteFile(MtpObjectHandle handle)
    {
        size_t orig_size = db.size();
        size_t new_size;

std::cout << __PRETTY_FUNCTION__ << " handle: " << handle << std::endl;

        if (db.at(handle).object_format == MTP_FORMAT_ASSOCIATION)
            inotify_rm_watch(inotify_fd, db.at(handle).watch_fd);

        new_size = db.erase(handle);

        if (orig_size > new_size) {
	   /* FIXME */
            /* Recursively remove children object from the DB as well.
             * we can safely ignore failures here, since the objects
             * would not be reachable anyway.
             */
	    for (std::map<MtpObjectHandle, DbEntry>::iterator i = db.begin(); i != db.end(); ++i) {
                if (i->second.parent == handle)
                    db.erase(i->first);
            }

            return MTP_RESPONSE_OK;
        }
        else
            return MTP_RESPONSE_GENERAL_ERROR;
    }

    virtual MtpResponseCode moveFile(MtpObjectHandle handle, MtpObjectHandle new_parent)
    {
	    std::cout << __PRETTY_FUNCTION__ << " handle: " << handle
                << " new parent: " << new_parent << std::endl;

        // change parent
        db.at(handle).parent = new_parent;

        return MTP_RESPONSE_OK;
    }

    /*
    virtual MtpResponseCode copyFile(MtpObjectHandle handle, MtpObjectHandle new_parent)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;

        // duplicate DbEntry
        // change parent

        return MTP_RESPONSE_OK
    }
    */

    virtual MtpObjectHandleList* getObjectReferences(MtpObjectHandle handle)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        return NULL;
    }

    virtual MtpResponseCode setObjectReferences(
        MtpObjectHandle handle,
        MtpObjectHandleList* references)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        return MTP_RESPONSE_OPERATION_NOT_SUPPORTED;    
    }

    virtual MtpProperty* getObjectPropertyDesc(
        MtpObjectProperty property,
        MtpObjectFormat format)
    {
std::cout << __PRETTY_FUNCTION__ << MtpDebug::getObjectPropCodeName(property) << std::endl;

        MtpProperty* result = NULL;
        switch(property)
        {
            case MTP_PROPERTY_STORAGE_ID: result = new MtpProperty(property, MTP_TYPE_UINT32); break;
            case MTP_PROPERTY_OBJECT_FORMAT: result = new MtpProperty(property, MTP_TYPE_UINT32); break;
            case MTP_PROPERTY_OBJECT_SIZE: result = new MtpProperty(property, MTP_TYPE_UINT32); break;
            case MTP_PROPERTY_WIDTH: result = new MtpProperty(property, MTP_TYPE_UINT32); break;
            case MTP_PROPERTY_HEIGHT: result = new MtpProperty(property, MTP_TYPE_UINT32); break;
            case MTP_PROPERTY_IMAGE_BIT_DEPTH: result = new MtpProperty(property, MTP_TYPE_UINT32); break;
            case MTP_PROPERTY_DISPLAY_NAME: result = new MtpProperty(property, MTP_TYPE_STR, true); break;
            case MTP_PROPERTY_OBJECT_FILE_NAME: result = new MtpProperty(property, MTP_TYPE_STR, true); break;
            default: break;                
        }
        
        return result;
    }

    virtual MtpProperty* getDevicePropertyDesc(MtpDeviceProperty property)
    {
std::cout << __PRETTY_FUNCTION__ << MtpDebug::getDevicePropCodeName(property) << std::endl;
        return new MtpProperty(MTP_DEVICE_PROPERTY_UNDEFINED, MTP_TYPE_UNDEFINED);
    }
    
    virtual void sessionStarted(MtpServer* server)
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
        local_server = server;
    }

    virtual void sessionEnded()
    {
std::cout << __PRETTY_FUNCTION__ << std::endl;
std::cout << "objects in db at session end: " << db.size() << std::endl;
        local_server = NULL;
    }
};
}

#endif // STUB_MTP_DATABASE_H_
