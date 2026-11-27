// Fails the test that leaks a file descriptor, and names the leaked fds.
//
// Why: the differential suites open kernel sockets next to ustack objects, and
// a leak there accumulates over the whole run. Past FD_SETSIZE a later test's
// FD_SET overflows its fd_set (stack smashing), a hard-coded "bad fd" becomes
// a live one, and a stray close() hits an fd another test now owns. The leak
// is reported on the test that causes it.
//
// Not flaky because the baseline is taken at OnTestStart, not at program
// start, so descriptors glibc or gtest open lazily on first use inside an
// earlier test are not charged to a later one; and the comparison is "fd
// numbers that exist now and did not before", so a test that closes and
// reopens the same number is not a leak. The suite order does not matter.
#include <dirent.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include <map>
#include <string>

namespace
{
    std::map<int, std::string> snapshot_fds()
    {
        std::map<int, std::string> fds;
        DIR* dir = opendir("/proc/self/fd");
        if (dir == nullptr)
        {
            return fds;
        }
        const int dir_fd = dirfd(dir);
        while (const dirent* entry = readdir(dir))
        {
            if (entry->d_name[0] == '.')
            {
                continue;
            }
            const int fd = std::stoi(entry->d_name);
            if (fd == dir_fd)
            {
                continue; // the directory stream's own descriptor
            }
            char target[256];
            const std::string path = std::string("/proc/self/fd/") + entry->d_name;
            const ssize_t n = readlink(path.c_str(), target, sizeof(target) - 1);
            fds[fd] = n < 0 ? "?" : std::string(target, static_cast<size_t>(n));
        }
        closedir(dir);
        return fds;
    }

    class FdLeakGuard : public ::testing::EmptyTestEventListener
    {
    public:
        void OnTestStart(const ::testing::TestInfo& /*info*/) override { _before = snapshot_fds(); }

        void OnTestEnd(const ::testing::TestInfo& info) override
        {
            const auto after = snapshot_fds();
            std::string leaked;
            for (const auto& [fd, target] : after)
            {
                if (_before.find(fd) == _before.end())
                {
                    leaked += "\n  fd " + std::to_string(fd) + " -> " + target;
                }
            }
            if (!leaked.empty())
            {
                ADD_FAILURE() << info.test_suite_name() << "." << info.name() << " leaked file descriptors:" << leaked;
            }
        }

    private:
        std::map<int, std::string> _before;
    };

    // Registered at static-init time because main() comes from gmock_main.
    const bool REGISTERED = []
    {
        ::testing::UnitTest::GetInstance()->listeners().Append(new FdLeakGuard);
        return true;
    }();
}
