//Update
package com.nimblix.attendance.repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.nimblix.attendance.entity.Attendance;
import com.nimblix.attendance.entity.AttendanceStatus;
import com.nimblix.attendance.entity.User;

public interface AttendanceRepository extends JpaRepository<Attendance, Long> {

        Optional<Attendance> findByUserAndDateAndCheckOutTimeIsNull(User user, LocalDate date);

        Optional<Attendance> findByUserIdAndDateAndCheckOutTimeIsNull(Long userId, LocalDate date);

        void deleteByUserId(Long userId);

        Optional<Attendance> findByUserAndDate(User user, LocalDate date);

        // Employee's own report — no JOIN FETCH needed (single user, already in
        // session)
        Page<Attendance> findByUserIdAndDateBetween(Long userId, LocalDate start, LocalDate end, Pageable pageable);

        // -------------------------------------------------------
        // Admin queries — JOIN FETCH user so employeeName is populated
        // -------------------------------------------------------

        @Query(value = "SELECT a FROM Attendance a JOIN FETCH a.user u", countQuery = "SELECT COUNT(a) FROM Attendance a")
        Page<Attendance> findAllWithUser(Pageable pageable);

        @Query(value = "SELECT a FROM Attendance a JOIN FETCH a.user u WHERE a.date = :date", countQuery = "SELECT COUNT(a) FROM Attendance a WHERE a.date = :date")
        Page<Attendance> findByDateWithUser(@Param("date") LocalDate date, Pageable pageable);

        @Query(value = "SELECT a FROM Attendance a JOIN FETCH a.user u WHERE a.status = :status", countQuery = "SELECT COUNT(a) FROM Attendance a WHERE a.status = :status")
        Page<Attendance> findByStatusWithUser(@Param("status") AttendanceStatus status, Pageable pageable);

        @Query(value = "SELECT a FROM Attendance a JOIN FETCH a.user u WHERE a.date = :date AND a.status = :status", countQuery = "SELECT COUNT(a) FROM Attendance a WHERE a.date = :date AND a.status = :status")
        Page<Attendance> findByDateAndStatusWithUser(@Param("date") LocalDate date,
                        @Param("status") AttendanceStatus status, Pageable pageable);

        @Query(value = "SELECT a FROM Attendance a JOIN FETCH a.user u WHERE a.date = :date AND a.late = true", countQuery = "SELECT COUNT(a) FROM Attendance a WHERE a.date = :date AND a.late = true")
        Page<Attendance> findByDateAndLateTrueWithUser(@Param("date") LocalDate date, Pageable pageable);

        @Query(value = "SELECT a FROM Attendance a JOIN FETCH a.user u WHERE a.date = :date AND a.earlyCheckout = true", countQuery = "SELECT COUNT(a) FROM Attendance a WHERE a.date = :date AND a.earlyCheckout = true")
        Page<Attendance> findByDateAndEarlyCheckoutTrueWithUser(@Param("date") LocalDate date, Pageable pageable);

        // Keep originals for any other usage
        Page<Attendance> findByDate(LocalDate date, Pageable pageable);

        Page<Attendance> findByDateBetween(LocalDate start, LocalDate end, Pageable pageable);

        Page<Attendance> findByStatus(AttendanceStatus status, Pageable pageable);

        Page<Attendance> findByDateAndStatus(LocalDate date, AttendanceStatus status, Pageable pageable);

        Page<Attendance> findByDateAndLateTrue(LocalDate date, Pageable pageable);

        Page<Attendance> findByDateAndEarlyCheckoutTrue(LocalDate date, Pageable pageable);

        long countByDate(LocalDate date);

        // -------------------------------------------------------
        // Auto-checkout: bulk update records still open after 9 h
        // -------------------------------------------------------
        @Modifying
        @Query("""
                        UPDATE Attendance a
                        SET    a.checkOutTime   = a.checkInTime + 9 HOUR  ,
                               a.totalWorkMinutes = 540                    ,
                               a.autoCheckedOut   = true
                        WHERE  a.checkOutTime IS NULL
                        AND    a.checkInTime  <= :threshold
                        """)
        int bulkAutoCheckout(@Param("threshold") LocalDateTime threshold);
}
